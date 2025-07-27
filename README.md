# Smart Contract Auditor

A comprehensive React-based security analysis tool for Solidity smart contracts that helps developers identify vulnerabilities, gas optimization opportunities, and adherence to best practices.

![Smart Contract Auditor](https://img.shields.io/badge/React-18+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-audit-red.svg)

## 🚀 Features

### Security Analysis
- **Vulnerability Detection**: Identifies critical security issues including:
  - Reentrancy attacks
  - Missing access controls
  - Integer overflow vulnerabilities
  - Unchecked external calls
  - tx.origin usage
  - Floating pragma versions

### Gas Optimization
- **Performance Analysis**: Detects gas inefficiencies such as:
  - Public vs external function visibility
  - Storage vs memory usage patterns
  - Loop optimization opportunities

### Best Practices
- **Code Quality Checks**: Evaluates adherence to Solidity best practices:
  - NatSpec documentation
  - Event logging implementation
  - Modifier usage for access control

### Risk Assessment
- **Comprehensive Scoring**: Provides a risk score (0-100) based on:
  - Critical vulnerabilities (25 points each)
  - High severity issues (15 points each)
  - Medium severity issues (8 points each)
  - Low severity issues (3 points each)

### Reporting
- **Detailed Reports**: Generates downloadable JSON audit reports
- **Interactive Interface**: Tabbed view for different analysis categories
- **Line Number References**: Pinpoints exact locations of issues

## 🛠️ Installation

### Prerequisites
- Node.js 16+ 
- React 18+
- Modern web browser

### Dependencies
```bash
npm install react lucide-react
# or
yarn add react lucide-react
```

### Setup
1. Clone or download the Smart Contract Auditor component
2. Install dependencies
3. Import and use the component in your React application:

```jsx
import SmartContractAuditor from './SmartContractAuditor';

function App() {
  return (
    <div className="App">
      <SmartContractAuditor />
    </div>
  );
}
```

## 📖 Usage

### Basic Usage
1. **Input Contract Code**: Paste your Solidity contract code into the text area
2. **Load Sample**: Use the "Load Sample" button to test with a vulnerable contract
3. **Run Audit**: Click "Audit Contract" to start the security analysis
4. **Review Results**: Examine the results in the overview panel and detailed tabs
5. **Download Report**: Generate a JSON report of findings

### Understanding Results

#### Risk Levels
- **Critical Risk (70-100)**: Immediate attention required
- **High Risk (50-69)**: Should be addressed before deployment
- **Medium Risk (30-49)**: Consider addressing for improved security
- **Low Risk (10-29)**: Minor issues or improvements
- **Minimal Risk (0-9)**: Good security posture

#### Severity Classifications
- **Critical**: Exploitable vulnerabilities that can lead to fund loss
- **High**: Serious security issues that compromise contract integrity
- **Medium**: Moderate security concerns or potential attack vectors
- **Low**: Minor security improvements or best practice violations

## 🔍 Detected Vulnerabilities

### Critical & High Severity
- **Reentrancy Attacks**: Detects external calls before state changes
- **Access Control Issues**: Identifies missing authorization checks
- **Integer Overflow**: Finds arithmetic operations without SafeMath

### Medium Severity
- **Unchecked External Calls**: Flags calls without return value verification
- **tx.origin Usage**: Warns against phishing-vulnerable authorization
- **Floating Pragma**: Identifies version lock issues

## 🎯 Gas Optimization Detection

- **Function Visibility**: Recommends external over public when appropriate
- **Storage Patterns**: Analyzes memory vs storage usage
- **Loop Optimization**: Identifies inefficient array length lookups

## 📊 Best Practices Evaluation

- **Documentation**: Checks for NatSpec comment presence
- **Event Logging**: Verifies important state changes emit events
- **Modifiers**: Ensures reusable access control patterns

## 🔧 Configuration

The auditor uses predefined patterns for vulnerability detection. To customize:

1. **Add New Patterns**: Extend the `vulnerabilityPatterns` array
2. **Modify Severity**: Adjust scoring in the risk calculation
3. **Custom Rules**: Add domain-specific security checks

```javascript
const customPattern = {
  id: 'custom_vulnerability',
  name: 'Custom Security Issue',
  severity: 'High',
  pattern: /your-regex-pattern/gm,
  description: 'Description of the issue',
  recommendation: 'How to fix it'
};
```

## 📋 Sample Output

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "summary": {
    "totalIssues": 5,
    "criticalCount": 1,
    "highCount": 2,
    "mediumCount": 1,
    "lowCount": 1,
    "riskScore": 55,
    "contractLines": 45
  },
  "vulnerabilities": [
    {
      "name": "Reentrancy Attack",
      "severity": "Critical",
      "description": "External call before state change",
      "recommendation": "Use checks-effects-interactions pattern"
    }
  ]
}
```

## 🚨 Limitations

- **Static Analysis Only**: Cannot detect runtime vulnerabilities
- **Pattern-Based**: May miss complex or novel attack vectors
- **Solidity Focus**: Designed specifically for Solidity contracts
- **No Formal Verification**: Not a substitute for professional audits

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-pattern`)
3. Add your vulnerability patterns or improvements
4. Test thoroughly with various contract examples
5. Submit a pull request

### Adding New Patterns
When contributing new vulnerability patterns:
- Include clear descriptions and recommendations
- Test with both vulnerable and safe code examples
- Document the security implications
- Assign appropriate severity levels

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and development purposes. It should not be considered a substitute for professional smart contract audits. Always conduct thorough testing and professional security reviews before deploying contracts to mainnet.

## 🔗 Resources

- [Solidity Security Considerations](https://docs.soliditylang.org/en/latest/security-considerations.html)
- [ConsenSys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [OpenZeppelin Security](https://blog.openzeppelin.com/security-audits/)
- [SWC Registry](https://swcregistry.io/)

## 📞 Support

For issues, questions, or contributions:
- Open an issue on GitHub.
- Review existing vulnerability patterns.
- Test with your smart contracts.
- Share feedback for improvements.

---

