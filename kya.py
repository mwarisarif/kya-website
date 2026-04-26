import uuid
import hashlib
import json
from datetime import datetime, timedelta, timezone
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# ============================================================
#  LAYER 1 — DID MANAGER (Agent Identity Registry)
# ============================================================

class DIDManager:
    def __init__(self):
        self.registry = {}

    def register_agent(self, name, owner, capabilities, spend_limit):
        did = f"did:kya:{uuid.uuid4().hex[:16]}"
        model_hash = hashlib.sha256(name.encode()).hexdigest()
        agent = {
            "did": did,
            "name": name,
            "owner": owner,
            "capabilities": capabilities,
            "spend_limit": spend_limit,
            "model_hash": model_hash,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "status": "active"
        }
        self.registry[did] = agent
        return agent

    def get_agent(self, did):
        return self.registry.get(did, None)

    def revoke_agent(self, did):
        if did in self.registry:
            self.registry[did]["status"] = "revoked"
            return True
        return False

    def list_agents(self):
        return list(self.registry.values())


# ============================================================
#  LAYER 2 — CREDENTIAL MANAGER (Permissions & Session Keys)
# ============================================================

class CredentialManager:
    def __init__(self):
        self.credentials = {}

    def issue_credential(self, agent_did, permissions, spend_limit, issuer):
        credential_id = f"vc:{uuid.uuid4().hex[:12]}"
        expiry = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        credential = {
            "credential_id": credential_id,
            "agent_did": agent_did,
            "issuer": issuer,
            "permissions": permissions,
            "spend_limit": spend_limit,
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expiry,
            "status": "valid"
        }
        self.credentials[credential_id] = credential
        return credential

    def verify_credential(self, credential_id):
        cred = self.credentials.get(credential_id)
        if not cred:
            return False, "Credential not found"
        if cred["status"] != "valid":
            return False, "Credential revoked"
        if datetime.now(timezone.utc).isoformat() > cred["expires_at"]:
            return False, "Credential expired"
        return True, "Valid"

    def revoke_credential(self, credential_id):
        if credential_id in self.credentials:
            self.credentials[credential_id]["status"] = "revoked"
            return True
        return False

    def list_credentials(self, agent_did):
        return [c for c in self.credentials.values() if c["agent_did"] == agent_did]


# ============================================================
#  LAYER 3 — BEHAVIOR MONITOR (Runtime Anomaly Detection)
# ============================================================

class BehaviorMonitor:
    def __init__(self, spend_limit):
        self.spend_limit = spend_limit
        self.total_spent = {}
        self.anomalies = []
        self.action_counts = {}

    def check_action(self, agent_did, action):
        action_type = action.get("type")
        amount = action.get("amount", 0)

        # Track cumulative spend
        self.total_spent[agent_did] = self.total_spent.get(agent_did, 0) + amount

        # Track action frequency
        key = f"{agent_did}:{action_type}"
        self.action_counts[key] = self.action_counts.get(key, 0) + 1

        # Anomaly Rule 1: Spend limit exceeded
        if self.total_spent[agent_did] > self.spend_limit:
            anomaly = {
                "agent_did": agent_did,
                "reason": "Spend limit exceeded",
                "total_spent": self.total_spent[agent_did],
                "limit": self.spend_limit,
                "action": action,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.anomalies.append(anomaly)
            return f"ANOMALY — Spend limit exceeded. Total: ${self.total_spent[agent_did]} / Limit: ${self.spend_limit}"

        # Anomaly Rule 2: Repeated action spam (>10 same actions)
        if self.action_counts[key] > 10:
            anomaly = {
                "agent_did": agent_did,
                "reason": f"Action spam detected: '{action_type}' called {self.action_counts[key]} times",
                "action": action,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.anomalies.append(anomaly)
            return f"ANOMALY — Spam detected on action '{action_type}'"

        return f"ALLOWED — Action: '{action_type}' | Amount: ${amount} | Total Spent: ${self.total_spent[agent_did]}"

    def get_anomalies(self, agent_did):
        return [a for a in self.anomalies if a["agent_did"] == agent_did]

    def get_total_spent(self, agent_did):
        return self.total_spent.get(agent_did, 0)


# ============================================================
#  LAYER 4 — AUDIT LOG (Tamper-Evident Trail)
# ============================================================

class AuditLog:
    def __init__(self):
        self.logs = {}

    def log(self, agent_did, action, status="executed"):
        entry = {
            "agent_did": agent_did,
            "action": action,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        entry["hash"] = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode()
        ).hexdigest()

        if agent_did not in self.logs:
            self.logs[agent_did] = []
        self.logs[agent_did].append(entry)

    def get_log(self, agent_did):
        return self.logs.get(agent_did, [])

    def verify_integrity(self, agent_did):
        entries = self.logs.get(agent_did, [])
        for entry in entries:
            stored_hash = entry["hash"]
            check = {k: v for k, v in entry.items() if k != "hash"}
            computed = hashlib.sha256(
                json.dumps(check, sort_keys=True).encode()
            ).hexdigest()
            if stored_hash != computed:
                return False, f"Tampered entry at {entry['timestamp']}"
        return True, "All entries intact"

    def export_log(self, agent_did):
        return json.dumps(self.get_log(agent_did), indent=2)


# ============================================================
#  LAYER 5 — TRUST SCORE (On-chain Reputation System)
# ============================================================

class TrustScore:
    def __init__(self):
        self.scores = {}

    def update(self, agent_did, success: bool):
        if agent_did not in self.scores:
            self.scores[agent_did] = {"success": 0, "failure": 0, "history": []}
        if success:
            self.scores[agent_did]["success"] += 1
        else:
            self.scores[agent_did]["failure"] += 1
        self.scores[agent_did]["history"].append({
            "result": "success" if success else "failure",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def get_score(self, agent_did):
        data = self.scores.get(agent_did, {"success": 0, "failure": 0})
        total = data["success"] + data["failure"]
        if total == 0:
            return 0.0
        return round((data["success"] / total) * 100, 2)

    def get_grade(self, agent_did):
        score = self.get_score(agent_did)
        if score >= 90:   return "A — Highly Trusted"
        elif score >= 75: return "B — Trusted"
        elif score >= 50: return "C — Moderate Risk"
        elif score >= 25: return "D — High Risk"
        else:             return "F — Untrusted"

    def get_full_report(self, agent_did):
        data = self.scores.get(agent_did, {"success": 0, "failure": 0, "history": []})
        return {
            "agent_did": agent_did,
            "score": self.get_score(agent_did),
            "grade": self.get_grade(agent_did),
            "total_interactions": data["success"] + data["failure"],
            "successes": data["success"],
            "failures": data["failure"],
            "history": data.get("history", [])
        }


# ============================================================
#  KYA SYSTEM — MAIN ORCHESTRATOR
# ============================================================

class KYASystem:
    def __init__(self):
        self.did_manager    = DIDManager()
        self.cred_manager   = CredentialManager()
        self.audit_log      = AuditLog()
        self.trust_score    = TrustScore()

    def register_and_issue(self, name, owner, capabilities, spend_limit):
        agent = self.did_manager.register_agent(name, owner, capabilities, spend_limit)
        credential = self.cred_manager.issue_credential(
            agent_did=agent["did"],
            permissions=capabilities,
            spend_limit=spend_limit,
            issuer="KYA_Authority"
        )
        return agent, credential

    def run_agent(self, agent_did, actions):
        agent = self.did_manager.get_agent(agent_did)
        if not agent:
            print("Agent not found.")
            return
        if agent["status"] == "revoked":
            print("Agent is revoked. Access denied.")
            return

        monitor = BehaviorMonitor(spend_limit=agent["spend_limit"])

        for action in actions:
            result = monitor.check_action(agent_did, action)
            status = "blocked" if "ANOMALY" in result else "executed"
            self.audit_log.log(agent_did, action, status)

            # Update trust score
            self.trust_score.update(agent_did, success=(status == "executed"))
            print(f"  [{status.upper()}] {result}")

        return monitor.get_anomalies(agent_did)


# ============================================================
#  MAIN — RUN THE FULL DEMO
# ============================================================

def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# ============================================================
#  STREAMLIT UI
# ============================================================

def init_session_state():
    """Initialize Streamlit session state"""
    if "kya_system" not in st.session_state:
        st.session_state.kya_system = KYASystem()
    if "selected_agent" not in st.session_state:
        st.session_state.selected_agent = None


def main_ui():
    """Main Streamlit UI"""
    st.set_page_config(page_title="KYA System - AI Agent Manager", layout="wide", initial_sidebar_state="expanded")
    
    init_session_state()
    kya = st.session_state.kya_system
    
    # Header
    st.title("🤖 KYA System - Know Your AI Agent")
    st.markdown("**AI Agent Registration, Credential Verification & Behavior Monitoring Platform**")
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Agent Management")
        menu = st.radio("Select Action:", [
            "📊 Dashboard",
            "✅ Register Agent",
            "🔐 Credentials",
            "▶️ Run Agent",
            "📋 Audit Logs",
            "📈 Trust Scores",
            "🔍 System Overview"
        ])
    
    # DASHBOARD
    if menu == "📊 Dashboard":
        st.header("Dashboard")
        
        agents = kya.did_manager.list_agents()
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Agents", len(agents))
        with col2:
            active = sum(1 for a in agents if a["status"] == "active")
            st.metric("Active Agents", active)
        with col3:
            st.metric("Total Credentials", sum(len(kya.cred_manager.list_credentials(a["did"])) for a in agents))
        with col4:
            st.metric("Total Audit Entries", sum(len(kya.audit_log.get_log(a["did"])) for a in agents))
        
        st.markdown("---")
        
        if agents:
            st.subheader("Registered Agents")
            agent_data = []
            for agent in agents:
                agent_data.append({
                    "Name": agent["name"],
                    "DID": agent["did"][:20] + "...",
                    "Status": agent["status"],
                    "Spend Limit": f"${agent['spend_limit']}",
                    "Capabilities": ", ".join(agent["capabilities"][:2]) + ("..." if len(agent["capabilities"]) > 2 else "")
                })
            
            st.dataframe(pd.DataFrame(agent_data), use_container_width=True)
        else:
            st.info("No agents registered yet. Go to 'Register Agent' to create one.")
    
    # REGISTER AGENT
    elif menu == "✅ Register Agent":
        st.header("Register New AI Agent")
        
        with st.form("register_form"):
            col1, col2 = st.columns(2)
            with col1:
                agent_name = st.text_input("Agent Name", value="TradeAgent_01", key="agent_name_input")
                owner = st.text_input("Owner Address", value="0x1234567890abcdef", key="owner_input")
            with col2:
                spend_limit = st.number_input("Spend Limit ($)", value=500.0, min_value=10.0, key="spend_input")
                capabilities = st.multiselect(
                    "Capabilities",
                    ["trade", "read_market", "execute_order", "analyze_data", "deploy_model"],
                    default=["trade", "read_market", "execute_order"],
                    key="cap_input"
                )
            
            submit = st.form_submit_button("🚀 Register Agent", use_container_width=True)
            
            if submit:
                if not agent_name or not owner or not capabilities:
                    st.error("Please fill in all fields!")
                else:
                    agent, credential = kya.register_and_issue(
                        name=agent_name,
                        owner=owner,
                        capabilities=capabilities,
                        spend_limit=spend_limit
                    )
                    
                    st.success("✅ Agent Registered Successfully!")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.info(f"**Agent DID:** `{agent['did']}`")
                    with col2:
                        st.info(f"**Credential ID:** `{credential['credential_id']}`")
                    
                    # Display details
                    agent_details = {
                        "Name": agent["name"],
                        "Status": agent["status"],
                        "Spend Limit": f"${agent['spend_limit']}",
                        "Owner": agent["owner"],
                        "Registered At": agent["registered_at"]
                    }
                    st.dataframe(pd.DataFrame([agent_details]))
                    
                    # Display credential
                    st.subheader("Credential Details")
                    cred_details = {
                        "Permissions": ", ".join(credential["permissions"]),
                        "Expires At": credential["expires_at"],
                        "Status": credential["status"]
                    }
                    st.json(cred_details)
    
    # CREDENTIALS
    elif menu == "🔐 Credentials":
        st.header("Credential Management")
        
        agents = kya.did_manager.list_agents()
        if not agents:
            st.warning("No agents registered yet.")
        else:
            agent_names = {a["did"]: a["name"] for a in agents}
            selected_did = st.selectbox("Select Agent", options=agents, format_func=lambda x: x["name"], key="agent_select_cred")
            
            credentials = kya.cred_manager.list_credentials(selected_did["did"])
            
            if credentials:
                st.subheader(f"Credentials for {selected_did['name']}")
                for cred in credentials:
                    with st.expander(f"📋 {cred['credential_id']}"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"**Status:** {cred['status']}")
                            st.write(f"**Permissions:** {', '.join(cred['permissions'])}")
                        with col2:
                            st.write(f"**Issued At:** {cred['issued_at'][:10]}")
                            st.write(f"**Expires At:** {cred['expires_at'][:10]}")
                        
                        # Verify credential
                        valid, msg = kya.cred_manager.verify_credential(cred["credential_id"])
                        if valid:
                            st.success(f"✅ {msg}")
                        else:
                            st.error(f"❌ {msg}")
                        
                        # Option to revoke
                        if st.button(f"🔒 Revoke {cred['credential_id'][:12]}", key=f"revoke_{cred['credential_id']}"):
                            kya.cred_manager.revoke_credential(cred["credential_id"])
                            st.success("Credential revoked!")
                            st.rerun()
            else:
                st.info("No credentials for this agent.")
    
    # RUN AGENT
    elif menu == "▶️ Run Agent":
        st.header("Run Agent & Monitor Behavior")
        
        agents = kya.did_manager.list_agents()
        if not agents:
            st.warning("No agents registered yet.")
        else:
            selected_agent = st.selectbox("Select Agent to Run", options=agents, format_func=lambda x: x["name"], key="agent_select_run")
            
            st.subheader("Define Actions")
            
            num_actions = st.number_input("Number of Actions", min_value=1, max_value=10, value=3, key="num_actions")
            
            actions = []
            for i in range(num_actions):
                col1, col2 = st.columns(2)
                with col1:
                    action_type = st.selectbox(f"Action {i+1} Type", ["read_market", "execute_order", "analyze_data"], key=f"action_type_{i}")
                with col2:
                    amount = st.number_input(f"Action {i+1} Amount ($)", value=0.0, min_value=0.0, key=f"action_amount_{i}")
                
                actions.append({"type": action_type, "amount": amount})
            
            if st.button("▶️ Execute Actions", use_container_width=True, type="primary"):
                st.info(f"Executing {num_actions} actions for {selected_agent['name']}...")
                
                monitor = BehaviorMonitor(spend_limit=selected_agent["spend_limit"])
                results = []
                
                for action in actions:
                    result = monitor.check_action(selected_agent["did"], action)
                    status = "blocked" if "ANOMALY" in result else "executed"
                    kya.audit_log.log(selected_agent["did"], action, status)
                    kya.trust_score.update(selected_agent["did"], success=(status == "executed"))
                    
                    results.append({
                        "Action": action["type"],
                        "Amount": f"${action['amount']}",
                        "Status": status.upper(),
                        "Message": result
                    })
                
                st.success("✅ Actions executed!")
                
                st.dataframe(pd.DataFrame(results), use_container_width=True)
                
                # Show anomalies if any
                anomalies = monitor.get_anomalies(selected_agent["did"])
                if anomalies:
                    st.error("⚠️ Anomalies Detected!")
                    for a in anomalies:
                        st.warning(f"**{a['reason']}** - {a['timestamp']}")
    
    # AUDIT LOGS
    elif menu == "📋 Audit Logs":
        st.header("Audit Trail & Log Verification")
        
        agents = kya.did_manager.list_agents()
        if not agents:
            st.warning("No agents registered yet.")
        else:
            selected_agent = st.selectbox("Select Agent", options=agents, format_func=lambda x: x["name"], key="agent_select_audit")
            
            logs = kya.audit_log.get_log(selected_agent["did"])
            
            if logs:
                # Verify integrity
                intact, msg = kya.audit_log.verify_integrity(selected_agent["did"])
                if intact:
                    st.success(f"✅ Integrity Check: {msg}")
                else:
                    st.error(f"❌ Integrity Check: {msg}")
                
                st.subheader(f"Audit Logs for {selected_agent['name']}")
                
                log_data = []
                for entry in logs:
                    log_data.append({
                        "Timestamp": entry["timestamp"][:19],
                        "Action": entry["action"]["type"],
                        "Amount": f"${entry['action']['amount']}",
                        "Status": entry["status"].upper(),
                        "Hash": entry["hash"][:16] + "..."
                    })
                
                st.dataframe(pd.DataFrame(log_data), use_container_width=True)
                
                # Export as JSON
                with st.expander("📥 Export as JSON"):
                    st.json(json.loads(kya.audit_log.export_log(selected_agent["did"])))
            else:
                st.info("No audit logs for this agent.")
    
    # TRUST SCORES
    elif menu == "📈 Trust Scores":
        st.header("Trust Score & Reputation System")
        
        agents = kya.did_manager.list_agents()
        if not agents:
            st.warning("No agents registered yet.")
        else:
            # Show all agents' trust scores
            st.subheader("All Agents - Trust Scores")
            
            trust_data = []
            for agent in agents:
                report = kya.trust_score.get_full_report(agent["did"])
                trust_data.append({
                    "Agent": agent["name"],
                    "Score": report["score"],
                    "Grade": report["grade"].split(" — ")[0],
                    "Successes": report["successes"],
                    "Failures": report["failures"],
                    "Total": report["total_interactions"]
                })
            
            if trust_data:
                df = pd.DataFrame(trust_data)
                st.dataframe(df, use_container_width=True)
                
                # Visualize trust scores
                if not df.empty:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        fig = px.bar(df, x="Agent", y="Score", title="Trust Scores", color="Score", 
                                    color_continuous_scale="RdYlGn", range_color=[0, 100])
                        st.plotly_chart(fig, use_container_width=True)
                    
                    with col2:
                        fig = px.pie(df, names="Agent", values="Total", title="Interactions by Agent")
                        st.plotly_chart(fig, use_container_width=True)
                
                # Detailed view
                st.markdown("---")
                st.subheader("Detailed Trust Report")
                
                selected_agent = st.selectbox("Select Agent for Details", options=agents, format_func=lambda x: x["name"], key="agent_select_trust")
                report = kya.trust_score.get_full_report(selected_agent["did"])
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Trust Score", f"{report['score']}%")
                with col2:
                    st.metric("Grade", report['grade'].split(" — ")[0])
                with col3:
                    st.metric("Successes", report['successes'])
                with col4:
                    st.metric("Failures", report['failures'])
    
    # SYSTEM OVERVIEW
    elif menu == "🔍 System Overview":
        st.header("System Overview")
        
        agents = kya.did_manager.list_agents()
        
        # Statistics
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Total Agents", len(agents))
        with col2:
            active = sum(1 for a in agents if a["status"] == "active")
            st.metric("Active", active)
        with col3:
            total_creds = sum(len(kya.cred_manager.list_credentials(a["did"])) for a in agents)
            st.metric("Credentials", total_creds)
        with col4:
            total_logs = sum(len(kya.audit_log.get_log(a["did"])) for a in agents)
            st.metric("Audit Entries", total_logs)
        with col5:
            avg_trust = sum(kya.trust_score.get_score(a["did"]) for a in agents) / len(agents) if agents else 0
            st.metric("Avg Trust Score", f"{avg_trust:.1f}%")
        
        st.markdown("---")
        
        # Agent Summary
        if agents:
            st.subheader("All Agents Summary")
            
            summary_data = []
            for agent in agents:
                logs = kya.audit_log.get_log(agent["did"])
                creds = kya.cred_manager.list_credentials(agent["did"])
                trust = kya.trust_score.get_score(agent["did"])
                
                summary_data.append({
                    "Name": agent["name"],
                    "Status": agent["status"],
                    "Spend Limit": f"${agent['spend_limit']}",
                    "Credentials": len(creds),
                    "Audit Entries": len(logs),
                    "Trust Score": f"{trust}%"
                })
            
            st.dataframe(pd.DataFrame(summary_data), use_container_width=True)


if __name__ == "__main__":
    main_ui()