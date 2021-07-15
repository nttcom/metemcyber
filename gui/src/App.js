/*
 *    Copyright 2021, NTT Communications Corp.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

import React from 'react';
import './App.css';
import Login from './containers/login';
import DefaultLayout from './containers/defaultLayout';
import { BrowserRouter, Route, Switch } from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.css';
import '@fortawesome/fontawesome-free/js/fontawesome';
import '@fortawesome/fontawesome-free/js/solid';
import '@fortawesome/fontawesome-free/js/regular';


function App() {
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

export default App;
