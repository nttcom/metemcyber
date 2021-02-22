import React, { useState } from 'react';
import { Nav, NavItem, NavLink } from 'reactstrap';
import { Route, Switch } from 'react-router-dom';
import './default.css';
import Account from './account';



function DefaultLayout(props) {
    const { ipcRenderer } = window

    const handleAccount = () => {
        props.history.push('/contents/account');
    }

    const handleLogout = () => {
        const retValue = ipcRenderer.sendSync('select-logout');
        console.log(retValue)
        props.history.push('/login');
    }

    return (
        <div>
            <Nav className="header-nav">
                <NavItem>
                    <NavLink onClick={handleAccount}>Account</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink onClick={handleLogout}>Logout</NavLink>
                </NavItem>
            </Nav>
            <Nav vertical className="side-nav">
                <NavItem>
                    <NavLink disabled href="#">CTIトークンの購入</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">チャレンジの実行</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">タスク(チャレンジ)のキャンセル</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">保有トークンの廃棄</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">新規CTIトークンの配布</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">チャレンジの受付開始・解除</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">発行トークンの追加委託・引取・登録取消</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">ローカルMISPデータからのCTIトークン自動配布</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">CTIトークンのパラメータ変更</NavLink>
                </NavItem>
            </Nav>
            <div className="main-content">
                <Switch>
                    <Route path="/contents/account" name="account" render={props => <Account {...props} />} />
                </Switch>
            </div>
        </div>
    );
}

export default DefaultLayout;