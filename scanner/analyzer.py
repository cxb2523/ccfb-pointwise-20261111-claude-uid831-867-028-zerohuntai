
import ast
import re
import os
from pathlib import Path
from collections import defaultdict

from scanner.ai_model import AIRiskScorer
from scanner.rule_store import get_rule_store, SEVERITY_DISPLAY
from utils.vulnerability_patterns import get_vulnerability_patterns
from utils.logger import get_logger

logger = get_logger()

# File extension -> custom-rule language key.
EXTENSION_TO_LANGUAGE = {
    '.py': 'python',
    '.js': 'javascript',
    '.php': 'php',
    '.java': 'java',
    '.c': 'c',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.go': 'go',
    '.rb': 'ruby',
}


class CodeAnalyzer:

    #Analyzer for static code analysis.
    def __init__(self, verbose=False):

        self.verbose = verbose
        self.vulnerability_patterns = get_vulnerability_patterns()
        self.ai_scorer = AIRiskScorer()

        # Custom rules are managed through the rule store (hot-reloaded by
        # mtime). Built-in pattern strings are mapped to their stable ids so
        # every finding can carry rule_id/rule_name metadata.
        self.rule_store = get_rule_store()
        self._builtin_by_pattern = {
            rule['pattern']: rule for rule in self.rule_store.get_builtin_rules()
        }

        # Rule snapshot pinned for the lifetime of a running scan. While set,
        # rule changes on disk never affect the in-flight scan; the store's
        # mtime check only runs when the next snapshot is taken.
        self._scan_snapshot = None

        logger.info("Initialized code analyzer")

    # -------------------------------------------------- scan snapshot control

    def begin_scan(self):
        """
        Pin the current enabled custom rules for the duration of a scan.

        Hot reload (mtime-based) happens here, at the scan boundary: rules
        added/toggled/removed after this call are not visible until the next
        scan begins, so a scan never changes caliber halfway through.
        Returns the frozen snapshot (a list of deep-copied rule dicts).
        """
        self._scan_snapshot = self.rule_store.get_enabled_custom_rules()
        logger.info("Scan started with %d enabled custom rule(s)",
                    len(self._scan_snapshot))
        return self._scan_snapshot

    def end_scan(self):
        """Release the scan snapshot so later scans pick up rule changes."""
        count = len(self._scan_snapshot) if self._scan_snapshot else 0
        self._scan_snapshot = None
        logger.info("Scan ended (released snapshot of %d rule(s))", count)

    def _active_custom_rules(self):
        """Rules that should govern this analysis: pinned snapshot or fresh."""
        if self._scan_snapshot is not None:
            return self._scan_snapshot
        # Ad-hoc analysis outside a scan boundary: take a fresh snapshot.
        return self.rule_store.get_enabled_custom_rules()

    
    def analyze_code(self, code_content, file_extension, file_path):

        vulnerabilities = []

        # Select analysis method based on file type
        if file_extension == '.py':
            # Python-specific analysis using AST
            vulnerabilities.extend(self._analyze_python_code(code_content, file_path))

        # Generic pattern-based analysis for all file types
        vulnerabilities.extend(self._analyze_patterns(code_content, file_extension, file_path))

        # Custom rules from the rule store (pinned snapshot during a scan).
        # Findings here already carry snapshotted rule metadata and their
        # configured severity, so they must NOT go through the AI scorer.
        custom_findings = self._analyze_custom_rules(code_content, file_extension, file_path)
        vulnerabilities.extend(custom_findings)
        custom_identities = {id(v) for v in custom_findings}

        # Use AI model to score the built-in findings only; custom rule
        # findings keep the severity snapshotted from the rule definition.
        if vulnerabilities:
            builtin_vulns = [v for v in vulnerabilities if id(v) not in custom_identities]
            if builtin_vulns:
                self._enrich_with_ai_scoring(builtin_vulns, code_content)
            # Freeze rule identity/severity onto every finding. Historical
            # reports render from these fields and never look the rule back up,
            # so deleting a rule leaves old reports intact.
            for vuln in vulnerabilities:
                self._snapshot_rule_metadata(vuln)

        return {
            'file': file_path,
            'extension': file_extension,
            'vulnerabilities': vulnerabilities
        }

    def _snapshot_rule_metadata(self, vuln):
        """
        Ensure the finding carries self-contained rule identity.

        rule_id, rule_name and severity are copied from the rule that fired
        and travel with the report forever; later rule edits/deletes do not
        rewrite history.
        """
        vuln.setdefault('rule_id', vuln.get('rule_id') or 'UNKNOWN')
        vuln.setdefault('rule_name', vuln.get('rule_name') or vuln.get('type', 'Unknown Rule'))
        # severity is always present; normalize nothing, just guarantee the key.
        vuln['severity'] = vuln.get('severity', 'Medium')

    def _analyze_custom_rules(self, code_content, file_extension, file_path):
        """Run the pinned custom-rule snapshot against one file's content."""
        vulnerabilities = []
        language = EXTENSION_TO_LANGUAGE.get(file_extension)
        code_lines = code_content.splitlines()

        for rule in self._active_custom_rules():
            if rule['language'] not in ('generic', 'common') and rule['language'] != language:
                continue
            try:
                compiled = re.compile(rule['pattern'])
                matches = compiled.finditer(code_content)
            except re.error as exc:
                # Patterns are validated at write time, so this is defensive.
                logger.error("Custom rule %s has invalid regex: %s",
                             rule.get('id'), exc)
                continue

            for match in matches:
                line_no = code_content.count('\n', 0, match.start()) + 1
                context = code_lines[line_no - 1] if 0 < line_no <= len(code_lines) else ""

                # All rule metadata is snapshotted from the frozen rule dict.
                vulnerabilities.append({
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'source': 'custom',
                    'type': rule['name'],
                    'file': file_path,
                    'line': line_no,
                    'code': context.strip(),
                    'description': rule.get('description') or f"Custom rule {rule['id']} matched",
                    'severity': SEVERITY_DISPLAY.get(rule['severity'], 'Medium'),
                    'confidence': 'High',
                })

        return vulnerabilities

    
    def _analyze_python_code(self, code_content, file_path):

        vulnerabilities = []
        
        try:
            # Parse the Python code into an AST
            tree = ast.parse(code_content)
            
            # Visitor to find dangerous function calls
            dangerous_funcs = {
                'exec': 'Command Execution',
                'eval': 'Command Execution', 
                'os.system': 'Command Execution',
                'os.popen': 'Command Execution',
                'subprocess.call': 'Command Execution',
                'subprocess.Popen': 'Command Execution',
                'pickle.loads': 'Deserialization',
                'yaml.load': 'Deserialization',
                'sqlite3.connect': 'SQL Injection (SQLite)',
                'mysql.connector.connect': 'SQL Injection (MySQL)',
                'psycopg2.connect': 'SQL Injection (PostgreSQL)',
                'pymongo.MongoClient': 'NoSQL Injection'
            }
            
            # Walk through the AST nodes
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check function calls
                    func_name = None
                    
                    # Get function name for various call types
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        # Handle module.function() style calls
                        if isinstance(node.func.value, ast.Name):
                            func_name = f"{node.func.value.id}.{node.func.attr}"
                    
                    # Check if function is in our dangerous list
                    if func_name in dangerous_funcs:
                        vuln_type = dangerous_funcs[func_name]
                        
                        # Get additional context (line number and code)
                        line_no = getattr(node, 'lineno', 0)
                        code_lines = code_content.splitlines()
                        context = code_lines[line_no - 1] if line_no > 0 and line_no <= len(code_lines) else ""
                        
                        vulnerabilities.append({
                            'type': vuln_type,
                            'file': file_path,
                            'line': line_no,
                            'code': context.strip(),
                            'description': f"Potentially dangerous function call: {func_name}",
                            'severity': 'Medium',  # Will be adjusted by AI scorer
                            'confidence': 'Medium'
                        })
                
                # Check for insecure use of input() in Python
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'input':
                    line_no = getattr(node, 'lineno', 0)
                    code_lines = code_content.splitlines()
                    context = code_lines[line_no - 1] if line_no > 0 and line_no <= len(code_lines) else ""
                    
                    vulnerabilities.append({
                        'type': 'User Input',
                        'file': file_path,
                        'line': line_no, 
                        'code': context.strip(),
                        'description': "Unvalidated user input from input() function",
                        'severity': 'Low',
                        'confidence': 'Low'
                    })
        
        except SyntaxError:
            # Handle syntax errors in the Python code
            logger.warning(f"Syntax error in Python file: {file_path}")
            vulnerabilities.append({
                'type': 'Syntax Error',
                'file': file_path,
                'line': 0,
                'code': '',
                'description': "Syntax error in Python file",
                'severity': 'Low',
                'confidence': 'High'
            })
        except Exception as e:
            # Handle other exceptions
            logger.error(f"Error analyzing Python code in {file_path}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return vulnerabilities
    
    def _analyze_patterns(self, code_content, file_extension, file_path):

        vulnerabilities = []
        
        try:
            # Check if we have patterns for this file type
            patterns = self.vulnerability_patterns.get(file_extension.replace('.', ''), [])
            if not patterns:
                # Use generic patterns if no language-specific ones
                patterns = self.vulnerability_patterns.get('generic', [])
                
            # Lines of code for context
            code_lines = code_content.splitlines()
            
            # Check each pattern
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                # Resolve the stable built-in rule identity for this pattern.
                builtin_rule = self._builtin_by_pattern.get(pattern)
                matches = re.finditer(pattern, code_content)

                for match in matches:
                    # Calculate line number
                    line_no = code_content.count('\n', 0, match.start()) + 1

                    # Get context (the line of code)
                    context = code_lines[line_no - 1] if line_no > 0 and line_no <= len(code_lines) else ""

                    # Create vulnerability entry. rule_id/rule_name are
                    # snapshotted onto the finding so reports stay complete
                    # even if rule definitions change later.
                    vulnerabilities.append({
                        'rule_id': builtin_rule['id'] if builtin_rule else 'UNKNOWN',
                        'rule_name': builtin_rule['name'] if builtin_rule else pattern_info['type'],
                        'source': 'builtin',
                        'type': pattern_info['type'],
                        'file': file_path,
                        'line': line_no,
                        'code': context.strip(),
                        'description': pattern_info['description'],
                        'severity': pattern_info['default_severity'],
                        'confidence': pattern_info['confidence']
                    })
        
        except Exception as e:
            logger.error(f"Error in pattern analysis for {file_path}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return vulnerabilities
    
    def _enrich_with_ai_scoring(self, vulnerabilities, code_content):
        """
        Use AI model to enrich and score the vulnerabilities.
            vulnerabilities (list): List of detected vulnerabilities
            code_content (str): Full code content for context
            
        Returns:
            None (modifies vulnerabilities in place)
        """
        for vuln in vulnerabilities:
            # Get AI assessment for this vulnerability
            ai_assessment = self.ai_scorer.assess_vulnerability(
                vuln['type'], 
                vuln['code'],
                vuln['description'],
                code_content
            )
            
            # Update the vulnerability with AI assessment
            vuln['severity'] = ai_assessment['severity']
            vuln['ai_explanation'] = ai_assessment['explanation']
            
            # AI may adjust confidence level
            if 'confidence' in ai_assessment:
                vuln['confidence'] = ai_assessment['confidence']
