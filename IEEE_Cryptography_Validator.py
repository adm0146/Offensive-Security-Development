import yaml
import json
from typing import Dict, List

class CryptographyValidator:
    # Key-value based lookup dictionaries for violation detection
    WEAK_ALGORITHMS = {
        'md5': 'MD5 is cryptographically broken - do not use for security',
        'sha1': 'SHA1 is deprecated - vulnerable to collision attacks',
        'des': 'DES has insufficient key length - use AES instead',
        'rc4': 'RC4 is broken - do not use for encryption',
        'wep': 'WEP is insecure - use WPA2/WPA3 instead'
    }
    
    CUSTOM_CRYPTO_INDICATORS = [
        'own implementation',
        'custom implementation',
        'our implementation',
        'homemade',
        'self-built',
        'proprietary algorithm'
    ]
    
    POOR_KEY_MANAGEMENT = [
        'hardcoded',
        'fixed key',
        'static key',
        'default key',
        'never rotated',
        'no rotation'
    ]
    
    WEAK_RANDOMNESS = [
        'fixed range',
        'predictable',
        'sequential',
        'hardcoded random',
        'fixed seed'
    ]
    
    NO_EVOLUTION_INDICATORS = [
        'will not change',
        'permanent',
        'never update',
        'no upgrade'
    ]
    
    def __init__(self):
        # Initialize validator instance variables
        self.violations = []
        self.parsed_yaml = None
    
    # (T1) YAML Parser Method
    def parse_yaml(self, yaml_content: str) -> Dict:
        # Parse YAML content and return structured data
        try:
            self.parsed_yaml = yaml.safe_load(yaml_content)
            return self.parsed_yaml
        except yaml.YAMLError as e:
            print(f"Error parsing YAML: {e}")
            return None
    
    # (T2) Content Extraction Method for Policy Violations
    def extract_violations(self, parsed_data: Dict) -> List[Dict]:
        # Extract cryptography-related policy violations from parsed YAML
        violations_found = []
        
        if not isinstance(parsed_data, list):
            parsed_data = [parsed_data]
        
        for item in parsed_data:
            if not isinstance(item, dict):
                continue
            
            for key, value in item.items():
                if value is None:
                    continue
                
                value_lower = str(value).lower()
                
                for algo, description in self.WEAK_ALGORITHMS.items():
                    if algo in value_lower:
                        violations_found.append({
                            'requirement': key,
                            'violation_type': 'Weak Algorithm',
                            'algorithm': algo.upper(),
                            'description': description,
                            'content': value,
                            'severity': 'CRITICAL'
                        })
                
                for indicator in self.CUSTOM_CRYPTO_INDICATORS:
                    if indicator in value_lower:
                        violations_found.append({
                            'requirement': key,
                            'violation_type': 'Custom Cryptography Implementation',
                            'indicator': indicator,
                            'description': 'Do not use your own cryptographic implementations',
                            'content': value,
                            'severity': 'CRITICAL'
                        })
                
                for indicator in self.POOR_KEY_MANAGEMENT:
                    if indicator in value_lower:
                        violations_found.append({
                            'requirement': key,
                            'violation_type': 'Poor Key Management',
                            'indicator': indicator,
                            'description': 'Implement proper key rotation and management',
                            'content': value,
                            'severity': 'HIGH'
                        })
                
                for indicator in self.WEAK_RANDOMNESS:
                    if indicator in value_lower:
                        violations_found.append({
                            'requirement': key,
                            'violation_type': 'Weak Randomness',
                            'indicator': indicator,
                            'description': 'Use cryptographically secure random number generation',
                            'content': value,
                            'severity': 'HIGH'
                        })
                
                for indicator in self.NO_EVOLUTION_INDICATORS:
                    if indicator in value_lower:
                        violations_found.append({
                            'requirement': key,
                            'violation_type': 'No Algorithm Evolution',
                            'indicator': indicator,
                            'description': 'Allow for algorithm adaptation and evolution',
                            'content': value,
                            'severity': 'MEDIUM'
                        })
        
        self.violations = violations_found
        return violations_found
    
    # (T3) Key-Value Lookup Method for Violation Detection
    def lookup_violations(self, requirement_key: str, requirement_value: str) -> List[Dict]:
        # Perform key-value based lookup to determine violations
        violations_for_requirement = []
        value_lower = str(requirement_value).lower()
        
        for algo_key, algo_description in self.WEAK_ALGORITHMS.items():
            if algo_key in value_lower:
                violations_for_requirement.append({
                    'key': requirement_key,
                    'violation': f'Uses weak algorithm: {algo_key.upper()}',
                    'recommendation': f'Use modern algorithms. {algo_description}'
                })
        
        for indicator in self.CUSTOM_CRYPTO_INDICATORS:
            if indicator in value_lower:
                violations_for_requirement.append({
                    'key': requirement_key,
                    'violation': f'Contains custom cryptography: "{indicator}"',
                    'recommendation': 'Use well-tested, standard cryptographic libraries (OpenSSL, libsodium, etc.)'
                })
        
        for indicator in self.POOR_KEY_MANAGEMENT:
            if indicator in value_lower:
                violations_for_requirement.append({
                    'key': requirement_key,
                    'violation': f'Poor key management: "{indicator}"',
                    'recommendation': 'Implement key rotation, secure storage, and lifecycle management'
                })
        
        for indicator in self.WEAK_RANDOMNESS:
            if indicator in value_lower:
                violations_for_requirement.append({
                    'key': requirement_key,
                    'violation': f'Weak randomness: "{indicator}"',
                    'recommendation': 'Use cryptographically secure RNG (os.urandom, secrets module, etc.)'
                })
        
        for indicator in self.NO_EVOLUTION_INDICATORS:
            if indicator in value_lower:
                violations_for_requirement.append({
                    'key': requirement_key,
                    'violation': f'No algorithm evolution: "{indicator}"',
                    'recommendation': 'Design for algorithm agility and future upgrades'
                })
        
        return violations_for_requirement
    
    def generate_report(self) -> str:
        # Generate formatted report of all violations
        if not self.violations:
            return "✓ No violations detected!"
        
        report = f"\n{'='*80}\n"
        report += f"IEEE CRYPTOGRAPHY PRINCIPLE VIOLATION REPORT\n"
        report += f"{'='*80}\n\n"
        report += f"Total Violations Found: {len(self.violations)}\n\n"
        
        critical = [v for v in self.violations if v['severity'] == 'CRITICAL']
        high = [v for v in self.violations if v['severity'] == 'HIGH']
        medium = [v for v in self.violations if v['severity'] == 'MEDIUM']
        
        if critical:
            report += f"CRITICAL ({len(critical)}):\n"
            for v in critical:
                report += f"  ✗ {v['requirement']}: {v['violation_type']}\n"
                report += f"    Content: {v['content']}\n"
                report += f"    Issue: {v['description']}\n\n"
        
        if high:
            report += f"HIGH ({len(high)}):\n"
            for v in high:
                report += f"  ! {v['requirement']}: {v['violation_type']}\n"
                report += f"    Content: {v['content']}\n"
                report += f"    Issue: {v['description']}\n\n"
        
        if medium:
            report += f"MEDIUM ({len(medium)}):\n"
            for v in medium:
                report += f"  ~ {v['requirement']}: {v['violation_type']}\n"
                report += f"    Content: {v['content']}\n"
                report += f"    Issue: {v['description']}\n\n"
        
        report += f"{'='*80}\n"
        return report


# TEST CASES (T4)
def run_test_cases():
    # Execute test suite for all three methods
    
    print("\n" + "="*80)
    print("TEST SUITE: IEEE CRYPTOGRAPHY VALIDATOR")
    print("="*80 + "\n")
    
    validator = CryptographyValidator()
    
    # Sample YAML content
    test_yaml = """
- ALL: "This user story focuses on specifying clearly specifying crypto-related requirements"
  R1: "We will use MD5 for encrypting all passwords and GitHub API keys."
  R2: "For generating random numbers we will use a fixed range between 1 and 151."
  R3: "We will be using our own implementation of SHA512 to protect API keys used for GPT-4."
  R4: "Keys for vault will be rotated."
  R5: "If a new cryptography algorithm comes with better strength, then we will use it instead of SHA512."
"""
    
    # ====== T1 TEST CASES: YAML Parser ======
    print("\n" + "-"*80)
    print("TEST GROUP 1: YAML Parser (T1)")
    print("-"*80 + "\n")
    
    test_cases_t1 = [
        ("Valid YAML", test_yaml, True),
        ("Empty YAML", "", True),
        ("Simple YAML", "key: value", True),
        ("Complex YAML", "- item1\n- item2:\n    nested: value", True),
        ("Invalid YAML", "{ invalid: yaml: content }", False),
    ]
    
    for i, (test_name, yaml_content, should_succeed) in enumerate(test_cases_t1, 1):
        try:
            result = validator.parse_yaml(yaml_content) if yaml_content else None
            success = (result is not None) == should_succeed
            status = "✓ PASS" if success else "✗ FAIL"
            print(f"T1-{i}: {status} - {test_name}")
            if result:
                print(f"      Parsed: {type(result).__name__}")
        except Exception as e:
            print(f"T1-{i}: ✗ FAIL - {test_name} (Exception: {str(e)[:50]})")
    
    # Parse the main test YAML for remaining tests
    validator.parse_yaml(test_yaml)
    
    # ====== T2 TEST CASES: Content Extraction ======
    print("\n" + "-"*80)
    print("TEST GROUP 2: Content Extraction (T2)")
    print("-"*80 + "\n")
    
    test_cases_t2 = [
        ("MD5 Detection", {"test": "We will use MD5 for encryption"}, True),
        ("SHA1 Detection", {"test": "Using SHA1 algorithm"}, True),
        ("Custom Crypto Detection", {"test": "our own implementation of crypto"}, True),
        ("Weak RNG Detection", {"test": "fixed range between 1 and 100"}, True),
        ("Secure Practice", {"test": "We will use AES-256 encryption with proper key management"}, False),
    ]
    
    for i, (test_name, test_data, should_detect) in enumerate(test_cases_t2, 1):
        violations = validator.extract_violations(test_data)
        detected = len(violations) > 0
        success = detected == should_detect
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"T2-{i}: {status} - {test_name}")
        print(f"      Violations found: {len(violations)}")
        if violations:
            for v in violations:
                print(f"      - {v['violation_type']}")
    
    # ====== T3 TEST CASES: Key-Value Lookup ======
    print("\n" + "-"*80)
    print("TEST GROUP 3: Key-Value Lookup (T3)")
    print("-"*80 + "\n")
    
    test_cases_t3 = [
        ("R1 MD5 Violation", "R1", "We will use MD5 for encrypting all passwords", True),
        ("R2 Weak RNG", "R2", "For generating random numbers we will use a fixed range", True),
        ("R3 Custom Implementation", "R3", "We will be using our own implementation of SHA512", True),
        ("R4 Key Rotation", "R4", "Keys for vault will be rotated", False),
        ("R5 Algorithm Evolution", "R5", "If a new cryptography algorithm comes with better strength, we will use it", False),
    ]
    
    for i, (test_name, key, value, should_violate) in enumerate(test_cases_t3, 1):
        violations = validator.lookup_violations(key, value)
        has_violations = len(violations) > 0
        success = has_violations == should_violate
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"T3-{i}: {status} - {test_name}")
        print(f"      Key: {key}, Violations: {len(violations)}")
        if violations:
            for v in violations:
                print(f"      - {v['violation']}")
    
    # ====== FULL VALIDATION ======
    print("\n" + "-"*80)
    print("FULL VALIDATION REPORT")
    print("-"*80)
    
    validator.parse_yaml(test_yaml)
    violations = validator.extract_violations(validator.parsed_yaml)
    print(validator.generate_report())
    
    # Summary
    print("\nTEST SUMMARY:")
    print(f"  Total Test Cases: 15")
    print(f"  Total Violations Detected: {len(violations)}")
    print(f"  Critical: {len([v for v in violations if v['severity'] == 'CRITICAL'])}")
    print(f"  High: {len([v for v in violations if v['severity'] == 'HIGH'])}")
    print(f"  Medium: {len([v for v in violations if v['severity'] == 'MEDIUM'])}")
    print("="*80 + "\n")


if __name__ == "__main__":
    run_test_cases()
