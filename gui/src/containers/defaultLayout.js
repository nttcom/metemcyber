import React, { useEffect, useState } from 'react';
import styled from 'styled-components';
import { Col, Row, Collapse, Container, Navbar, NavbarToggler, NavbarBrand, UncontrolledDropdown, DropdownToggle, DropdownMenu, DropdownItem, NavbarText, List, Nav, NavItem, NavLink, Toast, ToastBody, ToastHeader } from 'reactstrap';
import { Route, Switch } from 'react-router-dom';
import Account from './account';
import Buy from './buycti';
import ChallangeExecution from './Challange/execution';
import ChallangeCancel from './Challange/cancel';

let intervalId = null;

function DefaultLayout(props) {
    const { ipcRenderer } = window
    const [toastOpen, setToastOpen] = useState(false);
    const [challange, setChallange] = useState({});
    const [isOpen, setIsOpen] = useState(false);
    const toggle = () => setIsOpen(!isOpen);

    useEffect(() => {
        if (sessionStorage.getItem('searchText') === null) {
            sessionStorage.setItem('searchText', '');
        }
        if (sessionStorage.getItem('challange') === "true") {
            setChallangeInterval();
        }
    }, [])

    const handleAccount = () => {
        props.history.push('/contents/account');
    }

    const handleLogout = () => {
        const retValue = ipcRenderer.sendSync('select-logout');
        props.history.push('/');
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

    const handleNav = (e) => {
        props.history.push(e.target.id);
    }

    return (
        <div>
            <Navbar expand="md" style={{ backgroundColor: "#5f9ea0" }} className="sticky-top">
                <NavbarBrand href="/" className="text-white">
                    Metemcyber
                </NavbarBrand>
                <NavbarToggler onClick={toggle} />
                <Collapse isOpen={isOpen} navbar>
                    <Nav className="me-auto" navbar>
                        <UncontrolledDropdown nav inNavbar>
                            <DropdownToggle nav caret className="text-white">
                                User Menu
                            </DropdownToggle>
                            <DropdownMenu right>
                                <DropdownItem onClick={handleAccount}>Account</DropdownItem>
                                <DropdownItem onClick={handleLogout}>Logout</DropdownItem>
                            </DropdownMenu>
                        </UncontrolledDropdown>
                    </Nav>
                </Collapse>
            </Navbar>
            <Container fluid>
                <Row>
                    <Col xs="3">
                        <SideNav vertical>
                            <NavItem>
                                <NavLink onClick={handleNav} id="/contents/buy">CTIトークンの購入</NavLink>
                            </NavItem>
                            <NavItem>
                                <NavLink onClick={handleNav} id="/contents/challange/execution">チャレンジの実行</NavLink>
                            </NavItem>
                            <NavItem>
                                <NavLink onClick={handleNav} id="/contents/challange/cancel">タスク(チャレンジ)のキャンセル</NavLink>
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
                        </SideNav>
                    </Col>

                    <Col xs="9">
                        <Switch>
                            <Route path="/contents/account" name="account" render={props => <Account {...props} />} />
                            <Route path="/contents/buy" name="account" render={props => <Buy {...props} />} />
                            <Route path="/contents/challange/execution" name="challange-execution" render={props => <ChallangeExecution {...props} setChallangeInterval={setChallangeInterval} />} />
                            <Route path="/contents/challange/cancel" name="challange-cancel" render={props => <ChallangeCancel {...props} />} />
                        </Switch>
                    </Col>
                </Row>
            </Container>
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

export const SideNav = styled(Nav)`
    border-right: 1px solid #999999;
    height: 100vh;
    position: sticky;
    top: 0;
`;
