import React, { useState, useEffect } from 'react';
import { AlertTriangle, Shield, CheckCircle, XCircle, Info, FileText, Download, Upload } from 'lucide-react';
import './App.css';  // Path is relative to the component
const SmartContractAuditor = () => {
  const [contractCode, setContractCode] = useState('');
  const [auditResults, setAuditResults] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [selectedTab, setSelectedTab] = useState('vulnerabilities');

  // Sample contract for demonstration
  const sampleContract = `pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function withdraw(uint256 amount) public {
        // Reentrancy vulnerability
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Missing access control
    function changeOwner(address newOwner) public {
        owner = newOwner;
    }
    
    // Integer overflow potential
    function addBalance(uint256 amount) public {
        balances[msg.sender] += amount;
    }
}`;

  // Vulnerability detection patterns
  const vulnerabilityPatterns = [
    {
      id: 'reentrancy',
      name: 'Reentrancy Attack',
      severity: 'Critical',
      pattern: /\.call\{value.*?\}\(\s*""\s*\).*?balances.*?-=/gms,
      description: 'External call before state change can lead to reentrancy attacks',
      recommendation: 'Use checks-effects-interactions pattern or reentrancy guards'
    },
    {
      id: 'access_control',
      name: 'Missing Access Control',
      severity: 'High',
      pattern: /function\s+\w+.*?public.*?\{[^}]*owner\s*=/gms,
      description: 'Critical functions lack proper access control modifiers',
      recommendation: 'Add onlyOwner or appropriate access control modifiers'
    },
    {
      id: 'integer_overflow',
      name: 'Integer Overflow',
      severity: 'Medium',
      pattern: /\+=.*?\d+(?!.*SafeMath)/gm,
      description: 'Arithmetic operations without overflow protection',
      recommendation: 'Use SafeMath library or Solidity 0.8+ built-in checks'
    },
    {
      id: 'unchecked_external_call',
      name: 'Unchecked External Call',
      severity: 'Medium',
      pattern: /\.call\(.*?\);(?!\s*require)/gm,
      description: 'External calls without checking return value',
      recommendation: 'Always check return values of external calls'
    },
    {
      id: 'tx_origin',
      name: 'tx.origin Usage',
      severity: 'Medium',
      pattern: /tx\.origin/g,
      description: 'Using tx.origin for authorization is vulnerable to phishing',
      recommendation: 'Use msg.sender instead of tx.origin'
    },
    {
      id: 'fixed_compiler',
      name: 'Floating Pragma',
      severity: 'Low',
      pattern: /pragma solidity \^/g,
      description: 'Floating pragma can lead to compilation with different versions',
      recommendation: 'Lock pragma to specific compiler version'
    }
  ];

  // Gas optimization patterns
  const gasOptimizations = [
    {
      id: 'public_vs_external',
      name: 'Public vs External Functions',
      pattern: /function\s+\w+.*?public(?!.*view|.*pure)/gm,
      description: 'Public functions cost more gas than external when not called internally',
      suggestion: 'Use external visibility for functions not called internally'
    },
    {
      id: 'storage_vs_memory',
      name: 'Storage vs Memory',
      pattern: /mapping.*?public/gm,
      description: 'Consider memory usage patterns for gas optimization',
      suggestion: 'Use memory for temporary data, storage for persistent data'
    },
    {
      id: 'loop_optimization',
      name: 'Loop Gas Optimization',
      pattern: /for\s*\(.*?\.length.*?\)/gm,
      description: 'Array length lookup in loops wastes gas',
      suggestion: 'Cache array length before loop execution'
    }
  ];

  // Best practices checks
  const bestPractices = [
    {
      id: 'natspec_comments',
      name: 'NatSpec Documentation',
      pattern: /\/\*\*.*?\*\//gms,
      description: 'Functions should have proper NatSpec documentation',
      present: false
    },
    {
      id: 'event_logging',
      name: 'Event Logging',
      pattern: /event\s+\w+/gm,
      description: 'Important state changes should emit events',
      present: false
    },
    {
      id: 'modifier_usage',
      name: 'Modifier Usage',
      pattern: /modifier\s+\w+/gm,
      description: 'Access control should use modifiers for reusability',
      present: false
    }
  ];

  const analyzeContract = () => {
    setIsAnalyzing(true);
    
    setTimeout(() => {
      const vulnerabilities = [];
      const gasIssues = [];
      const practiceIssues = [];

      // Check vulnerabilities
      vulnerabilityPatterns.forEach(pattern => {
        const matches = contractCode.match(pattern.pattern);
        if (matches) {
          vulnerabilities.push({
            ...pattern,
            matches: matches.length,
            lines: findLineNumbers(contractCode, pattern.pattern)
          });
        }
      });

      // Check gas optimizations
      gasOptimizations.forEach(pattern => {
        const matches = contractCode.match(pattern.pattern);
        if (matches) {
          gasIssues.push({
            ...pattern,
            matches: matches.length,
            lines: findLineNumbers(contractCode, pattern.pattern)
          });
        }
      });

      // Check best practices
      bestPractices.forEach(practice => {
        const matches = contractCode.match(practice.pattern);
        practiceIssues.push({
          ...practice,
          present: !!matches,
          matches: matches ? matches.length : 0
        });
      });

      const totalIssues = vulnerabilities.length + gasIssues.length + 
                         practiceIssues.filter(p => !p.present).length;
      
      const criticalCount = vulnerabilities.filter(v => v.severity === 'Critical').length;
      const highCount = vulnerabilities.filter(v => v.severity === 'High').length;
      const mediumCount = vulnerabilities.filter(v => v.severity === 'Medium').length;
      const lowCount = vulnerabilities.filter(v => v.severity === 'Low').length;

      let riskScore = (criticalCount * 25) + (highCount * 15) + (mediumCount * 8) + (lowCount * 3);
      riskScore = Math.min(riskScore, 100);

      setAuditResults({
        vulnerabilities,
        gasIssues,
        practiceIssues,
        summary: {
          totalIssues,
          criticalCount,
          highCount,
          mediumCount,
          lowCount,
          riskScore,
          contractLines: contractCode.split('\n').length
        }
      });
      
      setIsAnalyzing(false);
    }, 2000);
  };

  const findLineNumbers = (code, pattern) => {
    const lines = code.split('\n');
    const matches = [];
    
    lines.forEach((line, index) => {
      if (pattern.test && pattern.test(line)) {
        matches.push(index + 1);
      }
    });
    
    return matches.slice(0, 3); // Return first 3 matches
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'text-red-600 bg-red-50 border-red-200',
      'High': 'text-orange-600 bg-orange-50 border-orange-200',
      'Medium': 'text-yellow-600 bg-yellow-50 border-yellow-200',
      'Low': 'text-blue-600 bg-blue-50 border-blue-200'
    };
    return colors[severity] || 'text-gray-600 bg-gray-50 border-gray-200';
  };

  const getRiskLevel = (score) => {
    if (score >= 70) return { level: 'Critical Risk', color: 'text-red-600', bgColor: 'bg-red-100' };
    if (score >= 50) return { level: 'High Risk', color: 'text-orange-600', bgColor: 'bg-orange-100' };
    if (score >= 30) return { level: 'Medium Risk', color: 'text-yellow-600', bgColor: 'bg-yellow-100' };
    if (score >= 10) return { level: 'Low Risk', color: 'text-blue-600', bgColor: 'bg-blue-100' };
    return { level: 'Minimal Risk', color: 'text-green-600', bgColor: 'bg-green-100' };
  };

  const generateReport = () => {
    if (!auditResults) return;
    
    const report = {
      timestamp: new Date().toISOString(),
      summary: auditResults.summary,
      vulnerabilities: auditResults.vulnerabilities,
      gasOptimizations: auditResults.gasIssues,
      bestPractices: auditResults.practiceIssues
    };
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'audit-report.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-7xl mx-auto p-6 bg-gray-50 min-h-screen">
      <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
        <div className="flex items-center gap-3 mb-6">
          <Shield className="w-8 h-8 text-blue-600" />
          <div>
            <h1 className="text-3xl font-bold text-gray-800">Smart Contract Auditor</h1>
            <p className="text-gray-600">Comprehensive security analysis for Solidity smart contracts</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Code Input Section */}
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h2 className="text-xl font-semibold text-gray-800">Contract Code</h2>
              <div className="flex gap-2">
                <button
                  onClick={() => setContractCode(sampleContract)}
                  className="px-3 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded"
                >
                  Load Sample
                </button>
                <button
                  onClick={() => setContractCode('')}
                  className="px-3 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded"
                >
                  Clear
                </button>
              </div>
            </div>
            
            <textarea
              value={contractCode}
              onChange={(e) => setContractCode(e.target.value)}
              className="w-full h-96 p-4 border border-gray-300 rounded-lg font-mono text-sm resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Paste your Solidity contract code here..."
            />
            
            <button
              onClick={analyzeContract}
              disabled={!contractCode.trim() || isAnalyzing}
              className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
            >
              {isAnalyzing ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent"></div>
                  Analyzing Contract...
                </>
              ) : (
                <>
                  <Shield className="w-5 h-5" />
                  Audit Contract
                </>
              )}
            </button>
          </div>

          {/* Results Overview */}
          <div className="space-y-4">
            <h2 className="text-xl font-semibold text-gray-800">Audit Results</h2>
            
            {auditResults ? (
              <div className="space-y-4">
                {/* Risk Score */}
                <div className={`p-4 rounded-lg border ${getRiskLevel(auditResults.summary.riskScore).bgColor}`}>
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-semibold text-gray-800">Security Risk Score</h3>
                      <p className={`text-2xl font-bold ${getRiskLevel(auditResults.summary.riskScore).color}`}>
                        {auditResults.summary.riskScore}/100
                      </p>
                      <p className={`text-sm ${getRiskLevel(auditResults.summary.riskScore).color}`}>
                        {getRiskLevel(auditResults.summary.riskScore).level}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-sm text-gray-600">Total Issues</p>
                      <p className="text-2xl font-bold text-gray-800">{auditResults.summary.totalIssues}</p>
                    </div>
                  </div>
                </div>

                {/* Issue Breakdown */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 bg-red-50 rounded-lg border border-red-200">
                    <p className="text-sm text-red-600">Critical</p>
                    <p className="text-xl font-bold text-red-800">{auditResults.summary.criticalCount}</p>
                  </div>
                  <div className="p-3 bg-orange-50 rounded-lg border border-orange-200">
                    <p className="text-sm text-orange-600">High</p>
                    <p className="text-xl font-bold text-orange-800">{auditResults.summary.highCount}</p>
                  </div>
                  <div className="p-3 bg-yellow-50 rounded-lg border border-yellow-200">
                    <p className="text-sm text-yellow-600">Medium</p>
                    <p className="text-xl font-bold text-yellow-800">{auditResults.summary.mediumCount}</p>
                  </div>
                  <div className="p-3 bg-blue-50 rounded-lg border border-blue-200">
                    <p className="text-sm text-blue-600">Low</p>
                    <p className="text-xl font-bold text-blue-800">{auditResults.summary.lowCount}</p>
                  </div>
                </div>

                <button
                  onClick={generateReport}
                  className="w-full py-2 px-4 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  Download Report
                </button>
              </div>
            ) : (
              <div className="p-8 text-center text-gray-500">
                <Shield className="w-16 h-16 mx-auto mb-4 opacity-30" />
                <p>Run an audit to see results</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Detailed Results */}
      {auditResults && (
        <div className="bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-semibold text-gray-800">Detailed Analysis</h2>
            <div className="flex border border-gray-300 rounded-lg overflow-hidden">
              <button
                onClick={() => setSelectedTab('vulnerabilities')}
                className={`px-4 py-2 text-sm font-medium ${
                  selectedTab === 'vulnerabilities'
                    ? 'bg-blue-600 text-white'
                    : 'bg-white text-gray-600 hover:bg-gray-50'
                }`}
              >
                Vulnerabilities ({auditResults.vulnerabilities.length})
              </button>
              <button
                onClick={() => setSelectedTab('gas')}
                className={`px-4 py-2 text-sm font-medium border-l ${
                  selectedTab === 'gas'
                    ? 'bg-blue-600 text-white'
                    : 'bg-white text-gray-600 hover:bg-gray-50'
                }`}
              >
                Gas Optimization ({auditResults.gasIssues.length})
              </button>
              <button
                onClick={() => setSelectedTab('practices')}
                className={`px-4 py-2 text-sm font-medium border-l ${
                  selectedTab === 'practices'
                    ? 'bg-blue-600 text-white'
                    : 'bg-white text-gray-600 hover:bg-gray-50'
                }`}
              >
                Best Practices
              </button>
            </div>
          </div>

          {/* Vulnerabilities Tab */}
          {selectedTab === 'vulnerabilities' && (
            <div className="space-y-4">
              {auditResults.vulnerabilities.length > 0 ? (
                auditResults.vulnerabilities.map((vuln, index) => (
                  <div key={index} className={`p-4 rounded-lg border ${getSeverityColor(vuln.severity)}`}>
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5" />
                        <h3 className="font-semibold">{vuln.name}</h3>
                        <span className="px-2 py-1 text-xs rounded-full bg-opacity-50">
                          {vuln.severity}
                        </span>
                      </div>
                      {vuln.lines && vuln.lines.length > 0 && (
                        <span className="text-sm opacity-75">
                          Lines: {vuln.lines.join(', ')}
                        </span>
                      )}
                    </div>
                    <p className="text-sm mb-2">{vuln.description}</p>
                    <p className="text-sm font-medium">
                      <strong>Recommendation:</strong> {vuln.recommendation}
                    </p>
                  </div>
                ))
              ) : (
                <div className="p-8 text-center text-gray-500">
                  <CheckCircle className="w-16 h-16 mx-auto mb-4 text-green-500" />
                  <p>No security vulnerabilities detected!</p>
                </div>
              )}
            </div>
          )}

          {/* Gas Optimization Tab */}
          {selectedTab === 'gas' && (
            <div className="space-y-4">
              {auditResults.gasIssues.length > 0 ? (
                auditResults.gasIssues.map((issue, index) => (
                  <div key={index} className="p-4 rounded-lg border border-yellow-200 bg-yellow-50">
                    <div className="flex items-center gap-2 mb-2">
                      <Info className="w-5 h-5 text-yellow-600" />
                      <h3 className="font-semibold text-yellow-800">{issue.name}</h3>
                    </div>
                    <p className="text-sm text-yellow-700 mb-2">{issue.description}</p>
                    <p className="text-sm font-medium text-yellow-800">
                      <strong>Suggestion:</strong> {issue.suggestion}
                    </p>
                  </div>
                ))
              ) : (
                <div className="p-8 text-center text-gray-500">
                  <CheckCircle className="w-16 h-16 mx-auto mb-4 text-green-500" />
                  <p>No gas optimization issues found!</p>
                </div>
              )}
            </div>
          )}

          {/* Best Practices Tab */}
          {selectedTab === 'practices' && (
            <div className="space-y-4">
              {auditResults.practiceIssues.map((practice, index) => (
                <div key={index} className={`p-4 rounded-lg border ${
                  practice.present 
                    ? 'border-green-200 bg-green-50' 
                    : 'border-gray-200 bg-gray-50'
                }`}>
                  <div className="flex items-center gap-2 mb-2">
                    {practice.present ? (
                      <CheckCircle className="w-5 h-5 text-green-600" />
                    ) : (
                      <XCircle className="w-5 h-5 text-gray-600" />
                    )}
                    <h3 className={`font-semibold ${
                      practice.present ? 'text-green-800' : 'text-gray-800'
                    }`}>
                      {practice.name}
                    </h3>
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      practice.present 
                        ? 'bg-green-200 text-green-800' 
                        : 'bg-gray-200 text-gray-600'
                    }`}>
                      {practice.present ? 'Implemented' : 'Missing'}
                    </span>
                  </div>
                  <p className={`text-sm ${
                    practice.present ? 'text-green-700' : 'text-gray-600'
                  }`}>
                    {practice.description}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SmartContractAuditor;
