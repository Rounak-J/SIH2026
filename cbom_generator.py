import json
import os
from fpdf import FPDF

def generate_cyclonedx(findings, output_path):
    """CycloneDX 1.6 CBOM Serializer"""
    components = []
    for f in findings:
        components.append({
            "type": "cryptographic-asset",
            "name": f['artefact'],
            "cryptoProperties": {
                "assetType": f['type'],
                "algorithm": f['artefact'],
                "quantumRiskLevel": f.get('risk', 'Unknown'),
                "remediation": f.get('remediation', '')
            }
        })
        
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": components
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(cbom, f, indent=2)

class PDFReport(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.cell(0, 10, 'S.Q.A.N. Executive Audit Report', 0, 1, 'C')
        
    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(findings, output_path):
    """Executive PDF Exporter"""
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Helvetica", size=10)
    
    pdf.cell(0, 10, "Cryptographic Asset Findings & Remediation:", 0, 1)
    
    for f in findings:
        text = f"File: {os.path.basename(f['file_path'])} (Line {f['line_number']})\n"
        text += f"Artefact: {f['artefact']} | Risk: {f.get('risk', 'N/A')}\n"
        text += f"Remediation: {f.get('remediation', 'N/A')}\n"
        pdf.multi_cell(0, 6, text)
        pdf.ln(2)
        
    pdf.output(output_path)
