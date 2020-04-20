import React from "react";
import { BrowserRouter as Router, Switch } from "react-router-dom";
import DefaultLayout from "Layouts/Default";
import Home from "Pages/Home";
import API from "Pages/API";
import Contribute from "Pages/Contribute";
import AuthProvider from "Providers/AuthProvider";
import Results from "Pages/Results";

const App = () => {
  return (
    <AuthProvider>
      <Router>
        <Switch>
          <DefaultLayout exact path="/" component={Home} />
          <DefaultLayout exact path="/API" component={API} />
          <DefaultLayout exact path="/contribute" component={Contribute} />
          <DefaultLayout exact path="/results" component={Results} />
        </Switch>
      </Router>
    </AuthProvider>
  );
};

export default App;
