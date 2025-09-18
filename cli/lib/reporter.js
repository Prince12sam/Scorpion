import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function generateReport(data, outputFile, format = 'json') {
  console.log(`Generating ${format.toUpperCase()} report...`);
  
  try {
    let reportContent;
    
    switch (format.toLowerCase()) {
      case 'json':
        reportContent = generateJSONReport(data);
        break;
      case 'xml':
        reportContent = generateXMLReport(data);
        break;
      case 'csv':
        reportContent = generateCSVReport(data);
        break;
      case 'html':
        reportContent = await generateHTMLReport(data);
        break;
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
    
    // Ensure output directory exists
    const outputDir = path.dirname(outputFile);
    await fs.mkdir(outputDir, { recursive: true });
    
    // Write report
    await fs.writeFile(outputFile, reportContent);
    
    console.log(`✅ Report generated: ${outputFile}`);
    return { success: true, file: outputFile, format };
  } catch (error) {
    console.error('Report generation failed:', error.message);
    throw error;
  }
}

function generateJSONReport(data) {
  const report = {
    report_metadata: {
      generated_at: new Date().toISOString(),
      tool: 'Scorpion Security Scanner',
      version: '1.0.0',
      format: 'json'
    },
    ...data
  };
  
  return JSON.stringify(report, null, 2);
}

function generateXMLReport(data) {
  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
  xml += '<security_report>\n';
  xml += `  <metadata>\n`;
  xml += `    <generated_at>${new Date().toISOString()}</generated_at>\n`;
  xml += `    <tool>Scorpion Security Scanner</tool>\n`;
  xml += `    <version>1.0.0</version>\n`;
  xml += `  </metadata>\n`;
  
  if (data.target) {
    xml += `  <target>${escapeXML(data.target)}</target>\n`;
  }
  
  if (data.vulnerabilities) {
    xml += '  <vulnerabilities>\n';
    for (const vuln of data.vulnerabilities) {
      xml += '    <vulnerability>\n';
      xml += `      <id>${escapeXML(vuln.id || 'N/A')}</id>\n`;
      xml += `      <title>${escapeXML(vuln.title || 'N/A')}</title>\n`;
      xml += `      <severity>${escapeXML(vuln.severity || 'N/A')}</severity>\n`;
      xml += `      <description>${escapeXML(vuln.description || 'N/A')}</description>\n`;
      if (vuln.cvss) {
        xml += `      <cvss>${vuln.cvss}</cvss>\n`;
      }
      if (vuln.port) {
        xml += `      <port>${vuln.port}</port>\n`;
      }
      xml += '    </vulnerability>\n';
    }
    xml += '  </vulnerabilities>\n';
  }
  
  if (data.summary) {
    xml += '  <summary>\n';
    Object.entries(data.summary).forEach(([key, value]) => {
      xml += `    <${key}>${escapeXML(String(value))}</${key}>\n`;
    });
    xml += '  </summary>\n';
  }
  
  xml += '</security_report>\n';
  return xml;
}

function generateCSVReport(data) {
  if (!data.vulnerabilities) {
    return 'No vulnerabilities data available for CSV export\n';
  }
  
  let csv = 'ID,Title,Severity,CVSS,Port,Service,Description,Remediation\n';
  
  for (const vuln of data.vulnerabilities) {
    const row = [
      escapeCSV(vuln.id || 'N/A'),
      escapeCSV(vuln.title || 'N/A'),
      escapeCSV(vuln.severity || 'N/A'),
      escapeCSV(String(vuln.cvss || 'N/A')),
      escapeCSV(String(vuln.port || 'N/A')),
      escapeCSV(vuln.service || 'N/A'),
      escapeCSV(vuln.description || 'N/A'),
      escapeCSV(vuln.remediation || 'N/A')
    ];
    csv += row.join(',') + '\n';
  }
  
  return csv;
}

async function generateHTMLReport(data) {
  const template = await getHTMLTemplate();
  
  let html = template;
  
  // Replace placeholders
  html = html.replace('{{GENERATED_AT}}', new Date().toISOString());
  html = html.replace('{{TARGET}}', escapeHTML(data.target || 'N/A'));
  html = html.replace('{{SCAN_TYPE}}', escapeHTML(data.type || 'N/A'));
  
  // Summary section
  if (data.summary) {
    let summaryHTML = '';
    if (data.summary.totalVulnerabilities !== undefined) {
      summaryHTML += `
        <div class="summary-card">
          <h3>Total Vulnerabilities</h3>
          <div class="summary-number">${data.summary.totalVulnerabilities}</div>
        </div>
        <div class="summary-card critical">
          <h3>Critical</h3>
          <div class="summary-number">${data.summary.criticalVulns || 0}</div>
        </div>
        <div class="summary-card high">
          <h3>High</h3>
          <div class="summary-number">${data.summary.highVulns || 0}</div>
        </div>
        <div class="summary-card medium">
          <h3>Medium</h3>
          <div class="summary-number">${data.summary.mediumVulns || 0}</div>
        </div>
        <div class="summary-card low">
          <h3>Low</h3>
          <div class="summary-number">${data.summary.lowVulns || 0}</div>
        </div>
      `;
    }
    html = html.replace('{{SUMMARY_CARDS}}', summaryHTML);
  } else {
    html = html.replace('{{SUMMARY_CARDS}}', '<p>No summary data available</p>');
  }
  
  // Vulnerabilities section
  if (data.vulnerabilities && data.vulnerabilities.length > 0) {
    let vulnHTML = '<div class="vulnerabilities-list">';
    
    for (const vuln of data.vulnerabilities) {
      const severityClass = (vuln.severity || 'unknown').toLowerCase();
      vulnHTML += `
        <div class="vulnerability-item ${severityClass}">
          <div class="vuln-header">
            <h3>${escapeHTML(vuln.title || 'Unknown Vulnerability')}</h3>
            <span class="severity-badge ${severityClass}">${escapeHTML(vuln.severity || 'Unknown')}</span>
          </div>
          <div class="vuln-details">
            <p><strong>ID:</strong> ${escapeHTML(vuln.id || 'N/A')}</p>
            ${vuln.cvss ? `<p><strong>CVSS:</strong> ${vuln.cvss}</p>` : ''}
            ${vuln.port ? `<p><strong>Port:</strong> ${vuln.port}</p>` : ''}
            ${vuln.service ? `<p><strong>Service:</strong> ${escapeHTML(vuln.service)}</p>` : ''}
            <p><strong>Description:</strong> ${escapeHTML(vuln.description || 'No description available')}</p>
            ${vuln.remediation ? `<p><strong>Remediation:</strong> ${escapeHTML(vuln.remediation)}</p>` : ''}
          </div>
        </div>
      `;
    }
    
    vulnHTML += '</div>';
    html = html.replace('{{VULNERABILITIES}}', vulnHTML);
  } else {
    html = html.replace('{{VULNERABILITIES}}', '<p>No vulnerabilities found.</p>');
  }
  
  return html;
}

async function getHTMLTemplate() {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scorpion Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .summary-card h3 {
            color: #666;
            margin-bottom: 10px;
            font-size: 0.9rem;
            text-transform: uppercase;
        }
        
        .summary-number {
            font-size: 2rem;
            font-weight: bold;
            color: #333;
        }
        
        .summary-card.critical .summary-number { color: #dc3545; }
        .summary-card.high .summary-number { color: #fd7e14; }
        .summary-card.medium .summary-number { color: #ffc107; }
        .summary-card.low .summary-number { color: #28a745; }
        
        .section {
            background: white;
            margin-bottom: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .section-header {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .section-header h2 {
            color: #495057;
            margin: 0;
        }
        
        .section-content {
            padding: 20px;
        }
        
        .vulnerability-item {
            border: 1px solid #dee2e6;
            border-radius: 6px;
            margin-bottom: 15px;
            overflow: hidden;
        }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }
        
        .vuln-header h3 {
            margin: 0;
            color: #495057;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-badge.critical {
            background: #dc3545;
            color: white;
        }
        
        .severity-badge.high {
            background: #fd7e14;
            color: white;
        }
        
        .severity-badge.medium {
            background: #ffc107;
            color: #212529;
        }
        
        .severity-badge.low {
            background: #28a745;
            color: white;
        }
        
        .severity-badge.unknown {
            background: #6c757d;
            color: white;
        }
        
        .vuln-details {
            padding: 15px;
        }
        
        .vuln-details p {
            margin-bottom: 8px;
        }
        
        .vuln-details strong {
            color: #495057;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9rem;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .summary {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦂 Scorpion Security Report</h1>
            <p>Generated on {{GENERATED_AT}}</p>
            <p>Target: {{TARGET}} | Scan Type: {{SCAN_TYPE}}</p>
        </div>
        
        <div class="summary">
            {{SUMMARY_CARDS}}
        </div>
        
        <div class="section">
            <div class="section-header">
                <h2>🔍 Vulnerabilities</h2>
            </div>
            <div class="section-content">
                {{VULNERABILITIES}}
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by Scorpion - Global Threat-Hunting Platform</p>
        </div>
    </div>
</body>
</html>
  `;
}

function escapeXML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeCSV(str) {
  const s = String(str);
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}