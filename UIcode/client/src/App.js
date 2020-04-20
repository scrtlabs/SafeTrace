import React from 'react';
import FileUpload from './components/FileUpload';
import Header from './components/header';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css';
import routes from './routes';
const App = () => (
  // eslint-disable-next-line 
  <div className='container mt-4'>
  
    {routes}
   
  </div>
);

export default App;
