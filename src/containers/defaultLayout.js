import React, { useEffect, useState } from 'react';
import { List, Nav, NavItem, NavLink, Toast, ToastBody, ToastHeader } from 'reactstrap';
import { Route, Switch } from 'react-router-dom';
import './default.css';
import Account from './account';
import Buy from './buycti';
import ChallangeExecution from './Challange/execution';

let intervalId = null;

function DefaultLayout(props) {
    const { ipcRenderer } = window
    const [toastOpen, setToastOpen] = useState(false);
    const [challange, setChallange] = useState({});

    useEffect(() => {
        if (sessionStorage.getItem('searchText') === null) {
            sessionStorage.setItem('searchText', '');
        }
        if (sessionStorage.getItem('challange') === "true") {
            setChallangeInterval();
        }
    }, [])

    const handleAccount = () => {
        window.location.href = '/contents/account';
    }

    const handleLogout = () => {
        const retValue = ipcRenderer.sendSync('select-logout');
        props.history.push('/login');
    }

    const toastToggle = () => {
        setToastOpen(false);
    }

    ipcRenderer.on('set-challange', (event, arg) => {
        console.log(arg);
        setChallange(arg);
        setToastOpen(true);
        clearInterval(intervalId);
        sessionStorage.setItem('challange', false);
    });

    const setChallangeInterval = () => {
        intervalId = setInterval(() => {
            ipcRenderer.send('get-challange');
        }, 1000);
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
                    <NavLink href="/contents/buy">CTIトークンの購入</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink href="/contents/challange/execution">チャレンジの実行</NavLink>
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
                    <Route path="/contents/buy" name="account" render={props => <Buy {...props} />} />
                    <Route path="/contents/challange/execution" name="challange-execution" render={props => <ChallangeExecution {...props} setChallangeInterval={setChallangeInterval} />} />
                </Switch>
            </div>
            <Toast
                className="bg-success"
                style={{
                    position: 'fixed',
                    zIndex: 100,
                    right: 0,
                    bottom: 0,
                    width: 300
                }}
                isOpen={toastOpen}>
                <ToastHeader toggle={toastToggle}>Job Status</ToastHeader>
                <ToastBody>
                    <div>
                        チャレンジの実行に成功しました。
                    </div>
                    <div>
                        <List type="unstyled">
                            <li>
                                受信URL：{challange.url}
                            </li>
                            <li>
                                トークン：{challange.token}
                            </li>
                            <li>
                                タイトル：{challange.title}
                            </li>
                            <li>
                                保存場所：{challange.dataDir}
                            </li>
                            <li>
                                チャレンジトークン：{challange.challangeToken}
                            </li>
                        </List>
                    </div>
                </ToastBody>
            </Toast>
        </div>
    );
}

export default DefaultLayout;