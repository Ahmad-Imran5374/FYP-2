import React, { useState } from 'react';
import axios from 'axios';
import './signUp.css';

function SignUp() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const handleSignup = async (e) => {
    e.preventDefault();

    if(password.length<8){
      alert('Password must be eight character Long')
      return;
    }
    if (password !== confirmPassword) {
      alert('Passwords do not match!');
      return;
    }

    try {
      const response = await axios.post('http://localhost:5000/signup', {
        email,
        password,
      });
      if (response.status === 201) {
        alert(response.data.message || 'Sign up successful!');
        window.location.href = '/login'; // Redirect to login page
      }
    } catch (error) {
      alert(error.response?.data?.error || 'Signup failed!');
    }
  };

  return (
    <div className="signup-container">
      <h1>IoT Attack Guard</h1>
      <h2>Sign Up</h2>
      <form className="signup-form" onSubmit={handleSignup}>
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Enter Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Re-Enter Password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
        />
        <button type="submit">SUBMIT</button>
      </form>
    </div>
  );
}

export default SignUp;
