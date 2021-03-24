import React, { Component, useState, useEffect } from 'react';
import './App.css';
import Login from './containers/login';
import DefaultLayout from './containers/defaultLayout';
import { BrowserRouter, Route, Switch } from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.css';


class App extends Component {

  render() {
    return (
      <BrowserRouter>
        <Switch>
          <Route path="/contents" name="Overview" render={props => <DefaultLayout {...props} />} />
          <Route path="/login" name="Home" render={props => <Login {...props} />} />
          <Route name="Home" render={props => <Login {...props} />} />
        </Switch>
      </BrowserRouter>
    );
  }

}

export default App;
