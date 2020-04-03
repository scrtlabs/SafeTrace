import React from "react";
import "./App.css";
import { BrowserRouter as Router, Switch } from "react-router-dom";
import DefaultLayout from "Layouts/Default";
import Home from "Pages/Home";
import API from "Pages/API";
import Contribute from "Pages/Contribute";

const App = () => {
  return (
    <Router>
      <Switch>
        <DefaultLayout exact path="/" component={Home} />
        <DefaultLayout exact path="/API" component={API} />
        <DefaultLayout exact path="/contribute" component={Contribute} />
      </Switch>
    </Router>
  );
};

export default App;
