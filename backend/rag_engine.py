import io
import json
import os
import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from pypdf import PdfReader
from dotenv import load_dotenv
from openai import OpenAI
from detectors import PromptInjectionDetector

load_dotenv()

class DocumentChunk(BaseModel):
    chunk_id: str
    page_number: int
    text: str
    provenance: str = "untrusted_pdf"
    is_tainted: bool = False
    injection_reasons: List[str] = []

class ExtractedClaim(BaseModel):
    claim_id: str
    statement: str
    evidence_text: str
    verdict: str  # "SUPPORTED" | "CONTRADICTED" | "MIXED" | "NOT_ENOUGH_EVIDENCE"
    verdict_method: str = "keyword_heuristic"
    confidence: float
    rationale: str = "Evidence sentence evaluated via keyword_heuristic matching."

class RAGPipeline:
    """
    RAG Document Processing Engine for AgentGuard.
    Extracts text from PDFs, creates semantic chunks, tracks provenance taint using
    the pluggable PromptInjectionDetector, and performs LLM-based claim-evidence retrieval.
    """

    def parse_pdf_bytes(self, pdf_bytes: bytes, filename: str = "document.pdf") -> List[DocumentChunk]:
        chunks: List[DocumentChunk] = []
        try:
            reader = PdfReader(io.BytesIO(pdf_bytes))
            for page_idx, page in enumerate(reader.pages):
                text = page.extract_text() or ""
                clean_text = text.strip()
                if not clean_text:
                    continue

                det_res = PromptInjectionDetector.detect(clean_text)
                chunks.append(DocumentChunk(
                    chunk_id=f"{filename}-p{page_idx + 1}",
                    page_number=page_idx + 1,
                    text=clean_text,
                    provenance="untrusted_pdf",
                    is_tainted=det_res.is_injection,
                    injection_reasons=det_res.reasons
                ))
        except Exception:
            text_val = pdf_bytes.decode("utf-8", errors="ignore").strip()
            if text_val:
                det_res = PromptInjectionDetector.detect(text_val)
                chunks.append(DocumentChunk(
                    chunk_id=f"{filename}-raw-1",
                    page_number=1,
                    text=text_val,
                    provenance="untrusted_pdf",
                    is_tainted=det_res.is_injection,
                    injection_reasons=det_res.reasons
                ))
        return chunks

    def retrieve_evidence_for_claims(self, chunks: List[DocumentChunk]) -> List[ExtractedClaim]:
        claims: List[ExtractedClaim] = []

        untainted_texts = [c.text.strip() for c in chunks if not c.is_tainted and c.text.strip()]
        source_texts = untainted_texts if untainted_texts else [c.text.strip() for c in chunks if c.text.strip()]
        combined_text = "\n\n".join(source_texts)

        if not combined_text:
            return [
                ExtractedClaim(
                    claim_id="claim-fallback-empty",
                    statement="No extractable text found in the provided document.",
                    evidence_text="Document contained no readable text chunks.",
                    verdict="NOT_ENOUGH_EVIDENCE",
                    verdict_method="fallback_handler",
                    confidence=0.50,
                    rationale="Fallback claim returned because document text was empty."
                )
            ]

        try:
            client = OpenAI(
                api_key=os.getenv("GROQ_API_KEY"),
                base_url="https://api.groq.com/openai/v1"
            )

            system_prompt = (
                "You are an expert research claim extraction engine. "
                "Extract up to 4 key factual claims or statements from the provided document text. "
                "Respond ONLY with a valid JSON array of objects, where each object has keys: "
                "'statement' (string), 'evidence_text' (string), "
                "'verdict' (one of: 'SUPPORTED', 'CONTRADICTED', 'MIXED', 'NOT_ENOUGH_EVIDENCE'), "
                "'confidence' (float between 0.0 and 1.0), and 'rationale' (string)."
            )

            response = client.chat.completions.create(
                model="openai/gpt-oss-120b",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Document Text:\n{combined_text[:12000]}"}
                ]
            )

            raw_output = (response.choices[0].message.content or "").strip()

            json_match = re.search(r"\[[\s\S]*\]", raw_output)
            if json_match:
                parsed_items = json.loads(json_match.group(0))
                valid_verdicts = {"SUPPORTED", "CONTRADICTED", "MIXED", "NOT_ENOUGH_EVIDENCE"}
                for idx, item in enumerate(parsed_items[:4], start=1):
                    if isinstance(item, dict) and item.get("statement"):
                        verdict_val = str(item.get("verdict", "SUPPORTED")).upper()
                        if verdict_val not in valid_verdicts:
                            verdict_val = "SUPPORTED"
                        try:
                          conf_val = float(item.get("confidence", 0.90))
                        except (TypeError, ValueError):
                            conf_val = 0.90

                        claims.append(ExtractedClaim(
                            claim_id=f"claim-{idx}",
                            statement=str(item["statement"]).strip(),
                            evidence_text=str(item.get("evidence_text", "Extracted from document chunks.")).strip(),
                            verdict=verdict_val,
                            verdict_method="groq_llm",
                            confidence=conf_val,
                            rationale=str(item.get("rationale", "Evaluated via Groq LLM claim extraction.")).strip()
                        ))
            else:
                lines = [
                    re.sub(r"^[\-\*\d\.\)\s]+", "", line).strip()
                    for line in raw_output.splitlines()
                    if len(line.strip()) > 15
                ]
                for idx, line in enumerate(lines[:4], start=1):
                    claims.append(ExtractedClaim(
                        claim_id=f"claim-{idx}",
                        statement=line,
                        evidence_text="Extracted from document chunks.",
                        verdict="SUPPORTED",
                        verdict_method="groq_llm",
                        confidence=0.85,
                        rationale="Extracted directly via Groq LLM."
                    ))

            if not claims:
                raise ValueError("LLM returned no extractable claims.")

            return claims

        except Exception as e:
            return [
                ExtractedClaim(
                    claim_id="claim-fallback-1",
                    statement="Fallback Claim: Document ingested and queued for baseline analysis (LLM extraction unavailable).",
                    evidence_text=combined_text[:200],
                    verdict="NOT_ENOUGH_EVIDENCE",
                    verdict_method="fallback_handler",
                    confidence=0.60,
                    rationale=f"Returned safe fallback claim due to LLM API error: {str(e)}"
                )
            ]
