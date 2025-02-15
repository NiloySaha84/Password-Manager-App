import streamlit as st
from password_manager import save_password, get_all_passwords, search_password, delete

st.title("Password Manager")


option = st.sidebar.selectbox("Choose an Action:", ["Add Password", "View All Passwords", "Search Password"])

if option == "Add Password":
    st.header("Add a New Password")
    website = st.text_input("Website")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Save"):
        if website and username and password:
            save_password(website, username, password)
            st.success("Password saved successfully!")
        else:
            st.warning("Please fill out all fields!")
elif option == "View All Passwords":
    st.header("All Saved Passwords")

    passwords = get_all_passwords()
    if passwords:
        for site, creds in passwords.items():
            if st.button("Delete"):
                delete(site)
            st.write(f"**Website:** {site}")
            st.write(f"Username: {creds['username']}")
            st.write(f"Password: {creds['password']}")
            st.markdown("---")
    else:
        st.info("No passwords saved yet.")

elif option == "Search Password":
    st.header("Search for a Password")
    search_site = st.text_input("Enter Website")
    if st.button("Search"):
        result = search_password(search_site)
        if result:
            st.write(f"**Website:** {search_site}")
            st.write(f"**Username:** {result['username']}")
            st.write(f"**Password:** {result['password']}")
        else:
            st.error("No password found for this website.")


st.sidebar.markdown("🛠️ **Secure Password Manager**")