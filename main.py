from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from parser import run_slither, parse_vulnerabilities
from llm_analyzer import analyze_with_llm
from pdf_generator import generate_pdf
import json
import tempfile
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

last_audit = {}

@app.post("/audit")
async def audit_contract(file: UploadFile = File(...)):
    global last_audit

    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.sol',
        delete=False
    ) as tmp:
        content = await file.read()
        tmp.write(content.decode('utf-8'))
        tmp_path = tmp.name

    try:
        slither_output = run_slither(tmp_path)
        slither_findings = parse_vulnerabilities(slither_output)

        with open(tmp_path, 'r') as f:
            contract_code = f.read()

        llm_result = analyze_with_llm(contract_code, slither_findings)
        llm_data = json.loads(llm_result)

        result = {
            "status": "success",
            "slither_findings": slither_findings,
            "llm_analysis": llm_data,
            "total_vulnerabilities": len(slither_findings) + len(llm_data["additional_vulnerabilities"]),
            "risk_score": llm_data["overall_risk_score"],
            "summary": llm_data["summary"]
        }

        last_audit = result
        return result

    finally:
        os.unlink(tmp_path)

@app.get("/download-report")
def download_report():
    if not last_audit:
        return {"error": "No audit run yet"}
    pdf_path = generate_pdf(last_audit)
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename="audit_report.pdf"
    )

@app.get("/")
def root():
    return {"message": "Smart Contract Auditor API running"}