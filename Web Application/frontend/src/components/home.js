import React from 'react';
import { Link } from 'react-router-dom';
import './home.css';

function Home() {
  return (
    <div className="home-container">
      <h1>Welcome to IoT Attack Guard</h1>
      <p>Detect and Prevent Cyber Attacks on IoT Devices.</p>
      <div className="home-buttons">
        <Link to="/signup">
          <button>Sign Up</button>
        </Link>
        <Link to="/login">
          <button>Login</button>
        </Link>
      </div>
    </div>
  );
}

export default Home;
