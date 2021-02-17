import React, { Component, useState, useEffect } from 'react';
import './App.css';
import Login from './containers/login';
import DefaultLayout from './containers/defaultLayout';
import { BrowserRouter, Route, Switch } from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.css';


//const Login = React.lazy(() => import('./containers/login.js'));

class App extends Component {

  render() {
    return (
    <BrowserRouter>
      <Switch>
        <Route exact path="/overview" name="Overview" render={props => <DefaultLayout {...props} />} />
        <Route path="/" name="Home" render={props => <Login {...props} />} />
      </Switch>
    </BrowserRouter>
    );
  }

}

export default App;
