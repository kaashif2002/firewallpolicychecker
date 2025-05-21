import re
import ipaddress
from collections import defaultdict
import streamlit as st
from fpdf import FPDF
import io
import time

# File parsing
def parse_config(uploaded_file):
    try:
        lines = uploaded_file.read().decode("utf-8").splitlines()
        return lines
    except Exception as e:
        st.error(f"Error parsing file {uploaded_file.name}: {str(e)}")
        return []

# Analysis Functions
def find_public_wan(lines):
    public_wans = []
    current_iface = None
    iface_block = {}

    for line in lines:
        line = line.strip()
        if line.startswith("edit"):
            current_iface = line.split()[1].strip('"')
            iface_block = {"name": current_iface}
        elif current_iface and line.startswith("set ip"):
            iface_block["ip"] = line.split("set ip")[-1].strip()
        elif current_iface and line.startswith("set allowaccess"):
            iface_block["access"] = line.split("set allowaccess")[-1].strip()
        elif current_iface and line.startswith("set status"):
            iface_block["status"] = line.split("set status")[-1].strip()
        elif line == "next" and current_iface:
            try:
                ip_field = iface_block.get("ip", "")
                if ip_field:
                    ip = ip_field.split()[0]
                    if ip and not ip.startswith("0.0.0.0"):
                        ip_obj = ipaddress.ip_address(ip)
                        if not ip_obj.is_private:
                            public_wans.append(iface_block.copy())
            except (ValueError, IndexError) as e:
                pass
            current_iface = None

    return public_wans

def find_shadowed_policies(lines):
    policy_blocks = []
    current_block = []
    in_policy_section = False
    in_policy = False
    current_id = None

    for line in lines:
        line = line.strip()
        if line == "config firewall policy":
            in_policy_section = True
        elif in_policy_section and line == "end":
            in_policy_section = False
        elif in_policy_section:
            if line.startswith("edit"):
                in_policy = True
                current_id = line
                current_block = [line]
            elif in_policy and line == "next":
                if not any("set comments" in l and "Created by VPN wizard" in l for l in current_block):
                    policy_blocks.append((current_id, current_block))
                in_policy = False
            elif in_policy:
                current_block.append(line)

    signatures = defaultdict(list)
    for edit_line, block in policy_blocks:
        sig = tuple(sorted([l for l in block if any(x in l for x in ["srcaddr", "dstaddr", "service", "action", "schedule"])]))
        if sig:  # Only consider policies with defined attributes
            policy_name = next((l.split("set name")[-1].strip().strip('"') for l in block if l.startswith("set name")), edit_line)
            signatures[sig].append((policy_name, block))

    duplicates = [v for v in signatures.values() if len(v) > 1]
    return duplicates

def find_insecure_services(lines):
    insecure_patterns = r'edit\s+"?(telnet|ftp|tftp|uucp)"?'
    return [line.strip() for line in lines if re.search(insecure_patterns, line, re.IGNORECASE)]

def find_subnet_overlaps(lines):
    subnet_objects = []
    current_name = None
    in_address_section = False

    for line in lines:
        stripped = line.strip()
        if stripped == "config firewall address":
            in_address_section = True
        elif stripped == "end" and in_address_section:
            in_address_section = False
        elif in_address_section:
            if stripped.startswith("edit"):
                current_name = stripped.split("edit", 1)[-1].strip().strip('"')
            elif current_name and "set subnet" in stripped:
                match = re.search(r'set subnet\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', stripped)
                if match:
                    try:
                        ip, mask = match.groups()
                        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                        subnet_objects.append((current_name, net))
                    except ValueError:
                        continue

    overlaps = []
    seen_pairs = set()
    for i in range(len(subnet_objects)):
        name1, net1 = subnet_objects[i]
        for j in range(i + 1, len(subnet_objects)):
            name2, net2 = subnet_objects[j]
            if net1.overlaps(net2) and net1 != net2:
                pair = tuple(sorted((name1, name2)))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    overlaps.append((name1, str(net1), name2, str(net2)))

    return overlaps

def find_unrestricted_outbound(lines):
    unrestricted = []
    in_policy = False
    current_block = []
    current_id = None
    
    for line in lines:
        stripped = line.strip()
        if stripped == "config firewall policy":
            in_policy = True
        elif in_policy and stripped == "end":
            in_policy = False
        elif in_policy:
            if stripped.startswith("edit"):
                current_id = stripped
                current_block = [stripped]
            elif stripped == "next":
                src_all = any("set srcaddr all" in l for l in current_block)
                dst_all = any("set dstaddr all" in l for l in current_block)
                action_allow = any("set action accept" in l for l in current_block)
                
                if src_all and dst_all and action_allow:
                    unrestricted.append((current_id, current_block.copy()))
                current_block = []
            else:
                current_block.append(stripped)
                
    return unrestricted

def find_rules_with_logging_off(lines):
    no_logging = []
    in_policy = False
    current_block = []
    current_id = ""
    
    for line in lines:
        stripped = line.strip()
        if stripped == "config firewall policy":
            in_policy = True
        elif in_policy and stripped == "end":
            in_policy = False
        elif in_policy:
            if stripped.startswith("edit"):
                current_id = stripped
                current_block = [stripped]
            elif stripped == "next":
                has_logging = False
                for l in current_block:
                    if "set logtraffic" in l:
                        has_logging = True
                        break
                        
                if not has_logging:
                    no_logging.append((current_id, current_block.copy()))
                current_block = []
            else:
                current_block.append(stripped)
                
    return no_logging

def find_inactive_rules(lines):
    inactive = []
    in_policy = False
    current_block = []
    current_id = ""
    
    for line in lines:
        stripped = line.strip()
        if stripped == "config firewall policy":
            in_policy = True
        elif in_policy and stripped == "end":
            in_policy = False
        elif in_policy:
            if stripped.startswith("edit"):
                current_id = stripped
                current_block = [stripped]
            elif stripped == "next":
                if any("set status disable" in l for l in current_block):
                    inactive.append((current_id, current_block.copy()))
                current_block = []
            else:
                current_block.append(stripped)
                
    return inactive

def find_unfiltered_vpn_access(lines):
    vpn_policies = []
    in_policy = False
    current_block = []
    current_id = ""
    
    vpn_patterns = [
        r'set name.*vpn', 
        r'set.*ipsec', 
        r'set.*ssl-vpn'
    ]
    
    for line in lines:
        stripped = line.strip()
        if stripped == "config firewall policy":
            in_policy = True
        elif in_policy and stripped == "end":
            in_policy = False
        elif in_policy:
            if stripped.startswith("edit"):
                current_id = stripped
                current_block = [stripped]
            elif stripped == "next":
                is_vpn = False
                for l in current_block:
                    if any(re.search(pattern, l, re.IGNORECASE) for pattern in vpn_patterns):
                        is_vpn = True
                        break
                
                if is_vpn and any("set srcaddr all" in l for l in current_block):
                    vpn_policies.append((current_id, current_block.copy()))
                current_block = []
            else:
                current_block.append(stripped)
                
    return vpn_policies

# PDF Report Generation
def generate_pdf_report(filename, results):
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"FortiGate Configuration Audit Report", ln=True, align='C')
    pdf.cell(0, 10, f"File: {filename}", ln=True, align='C')
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    
    # Summary
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.set_font("Arial", "", 10)
    
    issues_count = sum(1 for k, v in results.items() if v and k != "file_name")
    pdf.multi_cell(0, 6, f"The configuration audit identified {issues_count} categories of potential issues that may require attention.")
    pdf.ln(5)
    
    # Format for each section
    def add_section(title, items, description=""):
        pdf.set_font("Arial", "B", 12)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(0, 8, title, ln=True, fill=True)
        
        pdf.set_font("Arial", "I", 9)
        if description:
            pdf.multi_cell(0, 5, description)
            pdf.ln(2)
            
        pdf.set_font("Arial", "", 9)
        if items:
            if isinstance(items[0], tuple):  # For policy blocks
                for i, item in enumerate(items, 1):
                    if isinstance(item, tuple) and len(item) == 2:
                        policy_id, policy_block = item
                        pdf.set_font("Arial", "B", 9)
                        pdf.cell(0, 6, f"Item {i}: {policy_id}", ln=True)
                        pdf.set_font("Arial", "", 8)
                        for line in policy_block:
                            pdf.cell(5, 4, "", ln=0)  # Indent
                            pdf.cell(0, 4, line, ln=True)
                    else:
                        pdf.multi_cell(0, 5, str(item))
                    pdf.ln(2)
            elif isinstance(items[0], list) and len(items[0]) >= 2:  # For duplicate policies
                for i, group in enumerate(items, 1):
                    pdf.set_font("Arial", "B", 9)
                    pdf.cell(0, 6, f"Duplicate Group {i}", ln=True)
                    pdf.set_font("Arial", "", 8)
                    for name, block in group:
                        pdf.set_font("Arial", "I", 8)
                        pdf.cell(5, 4, "", ln=0)  # Indent
                        pdf.cell(0, 4, f"Policy: {name}", ln=True)
                        pdf.set_font("Arial", "", 8)
                        for line in block[:5]:  # Show first 5 lines only
                            pdf.cell(10, 4, "", ln=0)  # Double indent
                            pdf.cell(0, 4, line, ln=True)
                        if len(block) > 5:
                            pdf.cell(10, 4, "", ln=0)  # Double indent
                            pdf.cell(0, 4, "...", ln=True)
                    pdf.ln(2)
            elif len(items) > 0 and len(items[0]) == 4:  # For subnet overlaps
                for i, (name1, net1, name2, net2) in enumerate(items, 1):
                    pdf.multi_cell(0, 5, f"{i}. Overlap: '{name1}' ({net1}) <--> '{name2}' ({net2})")
                pdf.ln(2)
            else:  # For simple string lists
                for i, item in enumerate(items, 1):
                    pdf.multi_cell(0, 5, f"{i}. {item}")
                pdf.ln(2)
        else:
            pdf.set_text_color(0, 128, 0)
            pdf.multi_cell(0, 5, "No issues detected")
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
    
    # Add each section to the report
    add_section("Public WAN Interfaces", 
                results.get("public_wans", []),
                "Interfaces with public IP addresses that may be exposed to the internet.")
    
    add_section("Duplicate/Shadowed Policies", 
                results.get("duplicates", []),
                "Policies with identical source, destination, and service settings that may shadow each other.")
    
    add_section("Insecure Services", 
                results.get("insecure", []),
                "Services like telnet, FTP, TFTP, and UUCP that transmit data in cleartext.")
    
    add_section("Overlapping Subnet Ranges", 
                results.get("overlaps", []),
                "Address objects with overlapping IP ranges that may cause confusion or policy conflicts.")
    
    add_section("Unrestricted Outbound Access", 
                results.get("unrestricted", []),
                "Policies that allow unrestricted outbound access from all sources to all destinations.")
    
    add_section("Rules Without Logging", 
                results.get("no_logging", []),
                "Policies with logging disabled, reducing visibility into network traffic.")
    
    add_section("Inactive Rules", 
                results.get("inactive", []),
                "Policies that are configured but currently disabled.")
    
    add_section("Unfiltered VPN Access", 
                results.get("vpn_access", []),
                "VPN-related policies with overly permissive access controls.")
    
    # Add timestamp and page numbers
    pdf.set_font("Arial", "I", 8)
    pdf.set_y(-15)
    pdf.cell(0, 10, f"Generated on {time.strftime('%Y-%m-%d %H:%M:%S')} - Page {pdf.page_no()}", 0, 0, 'C')
    
    # Return the PDF as a buffer
    pdf_output = pdf.output(dest="S").encode("latin-1")
    buffer = io.BytesIO(pdf_output)
    return buffer

# Streamlit GUI
st.set_page_config(page_title="FortiGate Config Auditor", layout="wide")
st.title("🔍 FortiGate Configuration Audit Tool")
st.markdown("""
This tool analyzes FortiGate firewall configuration files to identify potential security issues, 
misconfigurations, and optimization opportunities.
""")

with st.expander("How to use this tool"):
    st.markdown("""
    1. Upload one or more FortiGate configuration files (.conf or .txt format)
    2. The tool will automatically analyze each file for common security issues
    3. Review the findings in each section
    4. Generate a PDF report for your records or further analysis
    
    ⚠️ **Note**: This tool processes your configuration files locally in your browser.
    No data is sent to external servers.
    """)

uploaded_files = st.file_uploader("Upload one or more FortiGate .conf files", 
                                 type=["conf", "txt"], 
                                 accept_multiple_files=True)

# Define advanced options
with st.expander("Advanced Options"):
    col1, col2 = st.columns(2)
    with col1:
        checks = {
            "public_wans": st.checkbox("Public WAN Interfaces", value=True),
            "duplicates": st.checkbox("Duplicate/Shadowed Policies", value=True),
            "insecure": st.checkbox("Insecure Services", value=True),
            "overlaps": st.checkbox("Overlapping Subnet Ranges", value=True),
            "unrestricted": st.checkbox("Unrestricted Outbound Access", value=True),
            "no_logging": st.checkbox("Rules Without Logging", value=True)
        }
    with col2:
        more_checks = {
            "inactive": st.checkbox("Inactive Rules", value=True),
            "vpn_access": st.checkbox("Unfiltered VPN Access", value=True)
        }
    checks.update(more_checks)

if uploaded_files:
    all_results = []
    
    progress_bar = st.progress(0)
    status_text = st.empty()

    for i, uploaded_file in enumerate(uploaded_files):
        progress = (i / len(uploaded_files)) * 100
        progress_bar.progress(int(progress))
        status_text.text(f"Processing file {i+1} of {len(uploaded_files)}: {uploaded_file.name}")
        
        try:
            lines = parse_config(uploaded_file)
            if not lines:
                st.error(f"Could not parse {uploaded_file.name}. The file may be empty or corrupted.")
                continue

            file_results = {"file_name": uploaded_file.name}
            
            # Perform selected checks
            if checks["public_wans"]:
                file_results["public_wans"] = find_public_wan(lines)
            
            if checks["duplicates"]:
                file_results["duplicates"] = find_shadowed_policies(lines)
            
            if checks["insecure"]:
                file_results["insecure"] = find_insecure_services(lines)
            
            if checks["overlaps"]:
                file_results["overlaps"] = find_subnet_overlaps(lines)
            
            if checks["unrestricted"]:
                file_results["unrestricted"] = find_unrestricted_outbound(lines)
            
            if checks["no_logging"]:
                file_results["no_logging"] = find_rules_with_logging_off(lines)
            
            if checks["inactive"]:
                file_results["inactive"] = find_inactive_rules(lines)
            
            if checks["vpn_access"]:
                file_results["vpn_access"] = find_unfiltered_vpn_access(lines)
            
            all_results.append(file_results)
        except Exception as e:
            st.error(f"Error processing {uploaded_file.name}: {str(e)}")
    
    progress_bar.progress(100)
    status_text.text("Processing complete!")
    time.sleep(0.5)
    status_text.empty()
    progress_bar.empty()
    
    # Display results for each file
    for file_results in all_results:
        filename = file_results["file_name"]
        st.header(f"📄 File: {filename}")
        
        tab_names = []
        if checks["public_wans"]: tab_names.append("WAN Interfaces")
        if checks["duplicates"]: tab_names.append("Duplicate Policies")
        if checks["insecure"]: tab_names.append("Insecure Services")
        if checks["overlaps"]: tab_names.append("Subnet Overlaps")
        if checks["unrestricted"]: tab_names.append("Unrestricted Access")
        if checks["no_logging"]: tab_names.append("No Logging")
        if checks["inactive"]: tab_names.append("Inactive Rules")
        if checks["vpn_access"]: tab_names.append("VPN Access")
        
        tabs = st.tabs(tab_names)
        
        tab_index = 0
        
        if checks["public_wans"]:
            with tabs[tab_index]:
                st.subheader("🌐 Public WAN Interfaces")
                public_wans = file_results.get("public_wans", [])
                if public_wans:
                    for wan in public_wans:
                        st.json(wan)
                else:
                    st.success("No public IPs detected.")
            tab_index += 1
        
        if checks["duplicates"]:
            with tabs[tab_index]:
                st.subheader("📛 Duplicate / Shadowed Policies")
                duplicates = file_results.get("duplicates", [])
                st.write(f"Found {len(duplicates)} potentially duplicate policy groups.")
                for i, group in enumerate(duplicates, start=1):
                    with st.expander(f"Duplicate Group #{i} ({len(group)} policies)"):
                        for policy_name, block in group:
                            st.markdown(f"**Policy:** {policy_name}")
                            st.code("\n".join(block))
            tab_index += 1
        
        if checks["insecure"]:
            with tabs[tab_index]:
                st.subheader("⚠️ Insecure Services Defined")
                insecure = file_results.get("insecure", [])
                if insecure:
                    for svc in insecure:
                        st.warning(svc)
                else:
                    st.success("No insecure services (e.g., telnet, ftp) defined.")
            tab_index += 1
        
        if checks["overlaps"]:
            with tabs[tab_index]:
                st.subheader("🔁 Overlapping Subnet Ranges")
                st.caption("This checks for address objects with IP ranges that overlap.")
                overlaps = file_results.get("overlaps", [])
                if overlaps:
                    for name1, net1, name2, net2 in overlaps:
                        st.error(f"Overlap Detected: `{name1}` ({net1}) <--> `{name2}` ({net2})")
                else:
                    st.success("No overlapping subnet ranges detected.")
            tab_index += 1
        
        if checks["unrestricted"]:
            with tabs[tab_index]:
                st.subheader("🚨 Unrestricted Outbound Access")
                unrestricted = file_results.get("unrestricted", [])
                st.write(f"Found {len(unrestricted)} policies allowing unrestricted outbound access.")
                for i, (policy_id, block) in enumerate(unrestricted, start=1):
                    with st.expander(f"Policy {policy_id}"):
                        st.code("\n".join(block))
            tab_index += 1
        
        if checks["no_logging"]:
            with tabs[tab_index]:
                st.subheader("📝 Rules Without Logging")
                no_logging = file_results.get("no_logging", [])
                st.write(f"Found {len(no_logging)} policies with logging disabled.")
                for i, (policy_id, block) in enumerate(no_logging, start=1):
                    with st.expander(f"Policy {policy_id}"):
                        st.code("\n".join(block))
            tab_index += 1
        
        if checks["inactive"]:
            with tabs[tab_index]:
                st.subheader("❌ Inactive Rules")
                inactive = file_results.get("inactive", [])
                st.write(f"Found {len(inactive)} disabled policies.")
                for i, (policy_id, block) in enumerate(inactive, start=1):
                    with st.expander(f"Policy {policy_id}"):
                        st.code("\n".join(block))
            tab_index += 1
        
        if checks["vpn_access"]:
            with tabs[tab_index]:
                st.subheader("🔓 Unfiltered VPN Access")
                vpn_access = file_results.get("vpn_access", [])
                st.write(f"Found {len(vpn_access)} VPN policies with potentially excessive permissions.")
                for i, (policy_id, block) in enumerate(vpn_access, start=1):
                    with st.expander(f"Policy {policy_id}"):
                        st.code("\n".join(block))
    
    # PDF Export section
    st.header("📄 Export Audit Report")
    
    col1, col2 = st.columns(2)
    with col1:
        pdf_filename = st.text_input("Enter desired filename (without .pdf):", 
                                    value="fortigate_audit")
    with col2:
        selected_file_index = st.selectbox(
            "Select file to export report for:",
            options=range(len(all_results)),
            format_func=lambda i: all_results[i]["file_name"]
        )
    
    if st.button("Generate & Download PDF"):
        with st.spinner("Generating PDF report..."):
            selected_results = all_results[selected_file_index]
            pdf_buffer = generate_pdf_report(
                selected_results["file_name"], 
                selected_results
            )
            
            st.download_button(
                label="📥 Download Audit PDF",
                data=pdf_buffer,
                file_name=f"{pdf_filename}.pdf",
                mime="application/pdf"
            )
            st.success("PDF report generated successfully!")