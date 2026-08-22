import React from 'react';
import ReactDOM from 'react-dom/client';
import Aplicación from './Aplicación';
import './index.css';
import './App.css';

// Renderizar la aplicación
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Aplicación />
  </React.StrictMode>
);