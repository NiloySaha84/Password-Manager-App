import streamlit as st
import pandas as pd
from datetime import datetime
import plotly.express as px
from password_manager import (
    PasswordManager,
    generate_strong_password,
    check_password_strength,
    analyze_password_health,
    export_passwords,
    import_passwords
)

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.pm = None
    st.session_state.last_activity = datetime.now()

st.markdown("""
<style>
    .password-strength-weak {color: #ff4444; font-weight: bold;}
    .password-strength-medium {color: #ffaa00; font-weight: bold;}
    .password-strength-strong {color: #00aa00; font-weight: bold;}
    .stButton>button {width: 100%;}
    .delete-btn>button {background-color: #ff4444; color: white;}
</style>
""", unsafe_allow_html=True)

st.title("🔐 Advanced Password Manager")
st.markdown("---")

if st.session_state.authenticated:
    time_diff = (datetime.now() - st.session_state.last_activity).seconds
    if time_diff > 900:  # 15 minutes
        st.session_state.authenticated = False
        st.session_state.pm = None
        st.warning("Session expired. Please login again.")
    else:
        st.session_state.last_activity = datetime.now()

# Authentication
if not st.session_state.authenticated:
    st.header("🔑 Authentication Required")

    col1, col2 = st.columns(2)
    with col1:
        auth_mode = st.radio("Select Mode", ["Login", "First Time Setup"])

    master_password = st.text_input("Master Password", type="password",
                                    help="This password encrypts all your data. Never forget it!")

    if auth_mode == "First Time Setup":
        confirm_password = st.text_input("Confirm Master Password", type="password")

        if st.button("Initialize Password Manager", type="primary"):
            if not master_password:
                st.error("Master password cannot be empty!")
            elif len(master_password) < 8:
                st.error("Master password must be at least 8 characters!")
            elif master_password != confirm_password:
                st.error("Passwords do not match!")
            else:
                try:
                    pm = PasswordManager(master_password)
                    st.session_state.authenticated = True
                    st.session_state.pm = pm
                    st.success("✅ Password Manager initialized successfully!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Initialization failed: {str(e)}")
    else:
        if st.button("Unlock", type="primary"):
            if master_password:
                try:
                    pm = PasswordManager(master_password)
                    # Verify by trying to get passwords
                    pm.get_all_passwords()
                    st.session_state.authenticated = True
                    st.session_state.pm = pm
                    st.success("✅ Unlocked successfully!")
                    st.rerun()
                except Exception as e:
                    st.error("❌ Invalid master password or corrupted data!")
            else:
                st.error("Please enter master password!")

    st.info("💡 **First time?** Select 'First Time Setup' to initialize your password manager.")
    st.stop()

pm = st.session_state.pm

st.sidebar.title("🛠️ Navigation")
option = st.sidebar.selectbox(
    "Choose an Action:",
    ["Dashboard", "Add Password", "View All Passwords", "Search Password",
     "Password Generator", "Import/Export", "Settings"]
)

if st.sidebar.button("🔒 Lock Manager"):
    st.session_state.authenticated = False
    st.session_state.pm = None
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 Quick Stats")
all_passwords = pm.get_all_passwords()
st.sidebar.metric("Total Passwords", len(all_passwords))
st.sidebar.metric("Last Activity", st.session_state.last_activity.strftime("%H:%M:%S"))

if option == "Dashboard":
    st.header("📊 Password Health Dashboard")

    if all_passwords:
        health_data = analyze_password_health(all_passwords)
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Passwords", health_data['total'])
        with col2:
            st.metric("Strong Passwords", health_data['strong'],
                      delta=f"{health_data['strong_percentage']:.1f}%")
        with col3:
            st.metric("Weak Passwords", health_data['weak'],
                      delta=f"-{health_data['weak_percentage']:.1f}%" if health_data['weak'] > 0 else "0%")
        with col4:
            st.metric("Duplicates", health_data['duplicates'],
                      delta="-" if health_data['duplicates'] > 0 else "✓")

        st.subheader("Password Strength Distribution")
        strength_df = pd.DataFrame({
            'Strength': ['Strong', 'Medium', 'Weak'],
            'Count': [health_data['strong'], health_data['medium'], health_data['weak']]
        })
        fig = px.pie(strength_df, values='Count', names='Strength',
                     color_discrete_map={'Strong': '#00aa00', 'Medium': '#ffaa00', 'Weak': '#ff4444'})
        st.plotly_chart(fig)

        # Weak passwords alert
        if health_data['weak_sites']:
            st.warning("⚠️ **Weak Passwords Detected**")
            st.write("Consider updating passwords for:", ", ".join(health_data['weak_sites']))

        # Duplicate passwords alert
        if health_data['duplicate_sites']:
            st.error("🔴 **Password Reuse Detected**")
            for pwd_hash, sites in health_data['duplicate_sites'].items():
                if len(sites) > 1:
                    st.write(f"Same password used for: {', '.join(sites)}")

        # Old passwords alert
        if health_data['old_sites']:
            st.info("📅 **Old Passwords** (>90 days)")
            st.write("Consider rotating:", ", ".join(health_data['old_sites']))
    else:
        st.info("No passwords saved yet. Add your first password to see health metrics!")

elif option == "Add Password":
    st.header("➕ Add New Password")

    col1, col2 = st.columns(2)
    with col1:
        website = st.text_input("Website/Service Name*")
        username = st.text_input("Username/Email*")
        category = st.selectbox("Category",
                                ["Social Media", "Email", "Banking", "Shopping",
                                 "Work", "Entertainment", "Other"])

    with col2:
        password_input = st.text_input("Password*", type="password")

        if st.button("Generate Strong Password"):
            generated = generate_strong_password()
            st.code(generated)
            st.info("Copy this password and paste it above!")

        if password_input:
            strength = check_password_strength(password_input)
            strength_text = {1: "Weak", 2: "Medium", 3: "Strong"}
            strength_class = {1: "weak", 2: "medium", 3: "strong"}
            st.markdown(f"Password Strength: <span class='password-strength-{strength_class[strength]}'>"
                        f"{strength_text[strength]}</span>", unsafe_allow_html=True)

        notes = st.text_area("Notes (Optional)", height=100)

    if st.button("💾 Save Password", type="primary"):
        if website and username and password_input:
            if pm.save_password(website, username, password_input, category, notes):
                st.success(f"✅ Password for {website} saved successfully!")
                st.balloons()
            else:
                st.error("Failed to save password. Please try again.")
        else:
            st.error("Please fill all required fields!")

elif option == "View All Passwords":
    st.header("🗃️ All Saved Passwords")

    passwords = pm.get_all_passwords()
    if passwords:
        # Filter by category
        categories = ["All"] + list(set(data.get('category', 'Other') for data in passwords.values()))
        selected_category = st.selectbox("Filter by Category", categories)

        # Sort options
        sort_by = st.selectbox("Sort by", ["Website (A-Z)", "Website (Z-A)",
                                           "Recently Added", "Category"])

        # Apply filters and sorting
        filtered_passwords = passwords if selected_category == "All" else {
            site: data for site, data in passwords.items()
            if data.get('category', 'Other') == selected_category
        }

        if sort_by == "Website (A-Z)":
            filtered_passwords = dict(sorted(filtered_passwords.items()))
        elif sort_by == "Website (Z-A)":
            filtered_passwords = dict(sorted(filtered_passwords.items(), reverse=True))
        elif sort_by == "Recently Added":
            filtered_passwords = dict(sorted(filtered_passwords.items(),
                                             key=lambda x: x[1].get('created_at', ''), reverse=True))
        elif sort_by == "Category":
            filtered_passwords = dict(sorted(filtered_passwords.items(),
                                             key=lambda x: x[1].get('category', 'Other')))

        for site, creds in filtered_passwords.items():
            with st.expander(f"🌐 {site} - {creds.get('category', 'Other')}"):
                col1, col2, col3 = st.columns([3, 2, 1])

                with col1:
                    st.write(f"**Username:** {creds['username']}")
                    if st.button(f"Show Password", key=f"show_{site}"):
                        st.code(creds['password'])

                    if creds.get('notes'):
                        st.write(f"**Notes:** {creds['notes']}")

                with col2:
                    strength = check_password_strength(creds['password'])
                    strength_text = {1: "⚠️ Weak", 2: "⚡ Medium", 3: "✅ Strong"}
                    st.write(f"**Strength:** {strength_text[strength]}")

                    if creds.get('created_at'):
                        created = datetime.fromisoformat(creds['created_at'])
                        days_old = (datetime.now() - created).days
                        st.write(f"**Age:** {days_old} days")

                with col3:
                    if st.button("🗑️ Delete", key=f"del_{site}"):
                        if pm.delete(site):
                            st.success(f"Deleted {site}")
                            st.rerun()
    else:
        st.info("No passwords saved yet. Go to 'Add Password' to get started!")

elif option == "Search Password":
    st.header("🔍 Search Password")

    search_term = st.text_input("Enter website, username, or keyword to search")

    if search_term:
        results = pm.search_passwords(search_term)
        if results:
            st.success(f"Found {len(results)} result(s)")

            for site, creds in results.items():
                with st.expander(f"🌐 {site}"):
                    st.write(f"**Username:** {creds['username']}")
                    st.write(f"**Category:** {creds.get('category', 'Other')}")
                    if st.button(f"Show Password", key=f"search_show_{site}"):
                        st.code(creds['password'])
                    if creds.get('notes'):
                        st.write(f"**Notes:** {creds['notes']}")
        else:
            st.warning("No passwords found matching your search.")

elif option == "Password Generator":
    st.header("🎲 Password Generator")

    col1, col2 = st.columns(2)
    with col1:
        length = st.slider("Password Length", 8, 32, 16)
        include_upper = st.checkbox("Include Uppercase (A-Z)", value=True)
        include_lower = st.checkbox("Include Lowercase (a-z)", value=True)

    with col2:
        include_digits = st.checkbox("Include Numbers (0-9)", value=True)
        include_symbols = st.checkbox("Include Symbols (!@#$...)", value=True)
        exclude_ambiguous = st.checkbox("Exclude Ambiguous (0, O, l, 1)", value=False)

    if st.button("🎲 Generate Password", type="primary"):
        if not any([include_upper, include_lower, include_digits, include_symbols]):
            st.error("Please select at least one character type!")
        else:
            password = generate_strong_password(
                length=length,
                include_upper=include_upper,
                include_lower=include_lower,
                include_digits=include_digits,
                include_symbols=include_symbols,
                exclude_ambiguous=exclude_ambiguous
            )
            st.success("Generated Password:")
            st.code(password)

            strength = check_password_strength(password)
            strength_text = {1: "Weak", 2: "Medium", 3: "Strong"}
            st.info(f"Password Strength: {strength_text[strength]}")

elif option == "Import/Export":
    st.header("📦 Import/Export Passwords")

    tab1, tab2 = st.tabs(["Export", "Import"])

    with tab1:
        st.subheader("Export Passwords")
        st.warning("⚠️ Exported files contain encrypted data. Keep them secure!")

        export_format = st.selectbox("Export Format", ["JSON (Encrypted)", "CSV (Decrypted - Use with caution!)"])

        if st.button("📥 Export"):
            export_data = export_passwords(pm, format=export_format.split()[0].lower())
            if export_data:
                st.download_button(
                    label="Download Export File",
                    data=export_data,
                    file_name=f"passwords_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{export_format.split()[0].lower()}",
                    mime="application/json" if "JSON" in export_format else "text/csv"
                )
                st.success("Export ready for download!")

    with tab2:
        st.subheader("Import Passwords")
        st.info("Import passwords from another password manager export")

        uploaded_file = st.file_uploader("Choose a file", type=['json', 'csv'])
        if uploaded_file is not None:
            if st.button("📤 Import"):
                success, message = import_passwords(pm, uploaded_file)
                if success:
                    st.success(message)
                    st.rerun()
                else:
                    st.error(message)

elif option == "Settings":
    st.header("⚙️ Settings")

    tab1, tab2, tab3 = st.tabs(["Security", "Backup", "About"])

    with tab1:
        st.subheader("Security Settings")

        if st.button("Change Master Password"):
            st.info("Feature coming soon! For now, export your passwords and re-initialize.")

        st.markdown("---")
        st.subheader("Security Recommendations")
        st.write("""
        - ✅ Use a strong, unique master password
        - ✅ Never share your master password
        - ✅ Regularly update weak passwords
        - ✅ Enable 2FA where possible
        - ✅ Backup your passwords regularly
        """)

    with tab2:
        st.subheader("Backup Settings")
        st.info("Regular backups ensure you never lose access to your passwords")

        if st.button("Create Backup Now"):
            backup_data = export_passwords(pm, format="json")
            if backup_data:
                st.download_button(
                    label="Download Backup",
                    data=backup_data,
                    file_name=f"password_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )

    with tab3:
        st.subheader("About")
        st.write("""
        ### Advanced Password Manager v2.0

        **Features:**
        - 🔐 Zero-knowledge encryption
        - 📊 Password health monitoring
        - 🎲 Strong password generation
        - 🔍 Advanced search capabilities
        - 📦 Import/Export functionality
        - 🏷️ Category organization

        **Security:**
        - Master password never stored
        - AES-256 encryption
        - Automatic session timeout
        - No cloud storage - all local     
        """)

# Footer
st.markdown("---")
st.markdown("🔒 Your data is encrypted and stored locally. Never forget your master password!")