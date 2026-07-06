import os
import glob
import json
import re

def get_latest_report(reports_dir):
    files = glob.glob(os.path.join(reports_dir, "reporte_vaa_*.html"))
    if not files:
        return None
    return max(files, key=os.path.getctime)

def parse_html_report(html_path):
    with open(html_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    findings = []


    pattern = re.compile(
        r'<div class="finding-title">(.*?)</div>\s*<div class="finding-url">([A-Z]+) (.*?)</div>',
        re.DOTALL | re.IGNORECASE
    )
    
    for match in pattern.finditer(content):
        vtype = match.group(1).strip()
        method = match.group(2).strip()
        url = match.group(3).strip()
        

        if "://" in url:
            path = "/" + url.split("://", 1)[1].split("/", 1)[-1]
        else:
            path = url
            
        findings.append({
            "type": vtype,
            "method": method,
            "path": path
        })
    return findings

def normalize_path(path):

    p = path.split('?')[0].rstrip('/')
    return p if p else '/'

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    reports_dir = os.path.join(base_dir, "reports")
    gt_path = os.path.join(base_dir, "tests", "lab_benchmark", "ground_truth.json")
    
    if not os.path.exists(gt_path):
        print(f"Error: No se encontro {gt_path}")
        return
        
    with open(gt_path, 'r', encoding='utf-8') as f:
        ground_truth = json.load(f)
        
    latest_report = get_latest_report(reports_dir)
    if not latest_report:
        print("Error: No se encontraron reportes HTML.")
        return
        
    print(f"[*] Evaluando reporte: {os.path.basename(latest_report)}")
    reported_findings = parse_html_report(latest_report)
    print(f"[*] Hallazgos parseados del HTML: {len(reported_findings)}")
    

    tp = 0
    fn = []
    fp = 0
    

    reported_by_path = {}
    for r in reported_findings:
        norm_p = normalize_path(r['path'])


        reported_by_path.setdefault(norm_p, []).append(r)
        
    must_detect_total = sum(1 for item in ground_truth if item.get('must_detect'))
    
    print("\n--- Resultados Detallados ---")
    for gt in ground_truth:
        is_must = gt.get('must_detect', False)
        expected_label = gt.get('expected_label', '')
        gt_path = gt.get('endpoint', '')
        gt_path_base = gt_path.split('{')[0].rstrip('/')
        

        matched = False
        aliases = {
            "ssrf": ["ssrf", "server-side request forgery"],
            "sql_injection": ["sql injection", "sqli", "sql_injection", "exploit confirmed", "suspicious server error"],
            "cross-site scripting": ["cross-site scripting", "xss"],
            "command_injection": ["command injection", "rce", "command_injection"],
            "bfla_vertical": ["bfla", "bfla_vertical", "privilege escalation", "exploit confirmed (role\":\"admin)"],
            "idor_confirmed": ["idor", "bola", "idor_confirmed", "sensitive data leakage"]
        }
        
        expected_lower = (expected_label or "").lower()
        valid_labels = aliases.get(expected_lower, [expected_lower])

        for rep_path, reps in reported_by_path.items():
            if rep_path.startswith(gt_path_base):
                if expected_label and any(any(val in r['type'].lower() for val in valid_labels) for r in reps):
                    matched = True
                    break
                elif not expected_label:
                    matched = True
                    break
                    
        if is_must:
            if matched:
                tp += 1
                print(f"[OK] TP: {gt_path} ({gt['category']})")
            else:
                fn.append(gt)
                print(f"[FAIL] FN: {gt_path} ({gt['category']})")
        else:
            if matched:
                fp += 1
                print(f"[FP] FP: {gt_path} - Se reporto algo en un SAFE endpoint!")
            else:
                print(f"[OK] TN: {gt_path} (SAFE)")

    print("\n=== VAA Benchmark Score ===")
    print(f"TP: {tp}/{must_detect_total} ({tp/must_detect_total*100:.1f}%)")
    print(f"FN: {len(fn)}/{must_detect_total}")
    print(f"FP: {fp}")
    
    if fn:
        print("\nFaltan por detectar:")
        for missing in fn:
            print(f"  - {missing['endpoint']} ({missing['category']})")

if __name__ == "__main__":
    main()
