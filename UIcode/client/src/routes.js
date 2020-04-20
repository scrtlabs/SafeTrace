'use strict'
/* Importing the node modules, child components, services and controllers used */
import React, { Component } from 'react';
import ReactDOM from 'react-dom';
// Import routing components

import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';


import signin from './components/signin'
import signout from './components/signout'
import home from './components/home'
import API from './components/API'




export default <Router >
	<div>
		<Switch>
			<Route exact path="/" component={home} />
			<Route exact path="/API" component={API} />
			<Route exact path="/signin" component={signin} />
			<Route exact path="/signout" component={signout} />
				
		</Switch>
	</div>
</Router>
