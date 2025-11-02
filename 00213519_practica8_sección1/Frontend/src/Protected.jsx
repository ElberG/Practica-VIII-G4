// Protected.jsx

import React, { useEffect, useState } from "react";
import API from "../utils/api.jsx"; 

const Protected = () => {
  const [message, setMessage] = useState("");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await API.get("/protected");
        setMessage(response.data.message);
      } catch (err) {
        console.error(err);
      }
    };
    fetchData();
  }, []);

  return <h1>{message}</h1>;
};

export default Protected;