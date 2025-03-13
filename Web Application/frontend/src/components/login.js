import React, { useState } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import "./login.css";

function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      // Login functionality
      const response = await axios.post("http://localhost:5000/login", {
        email,
        password,
      });
      if (response.status === 200) {
        alert(response.data.message || "Login successful!");
        localStorage.setItem("token", response.data.token); // Store token in local storage
        window.location.href = "/dashboard"; // Redirect to dashboard
      }
    } catch (error) {
      alert(error.response?.data?.error || "Login failed!");
    }
  };

  return (
    <div className="login-container">
      <h1>IoT Attack Guard</h1>
      <h2>Login</h2>
      <form className="login-form" onSubmit={handleSubmit}>
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <button type="submit">LOGIN</button>
      </form>
      <p className="toggle-auth">
        Don't have an account?{" "}
        <Link to="/signup">Sign Up</Link> {/* Redirects to signup page */}
      </p>
    </div>
  );
}

export default Login;
