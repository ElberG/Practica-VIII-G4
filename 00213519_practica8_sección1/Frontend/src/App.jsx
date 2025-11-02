import { useState } from 'react'
import { BrowserRouter as Router, Routes, Route } from "react-router-dom"; 
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import Login from "./Login";
import Protected from "./Protected";

const App = () => (
  <Router>
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/protected" element={<Protected />} />
    </Routes>
  </Router>
);

export default App
