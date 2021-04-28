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

    ipcRenderer.once('set-challange', (event, arg) => {
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
            <Container fluid style={{ paddingLeft: "0px" }}>
                <Row>
                    <ColSideNav xs="2">
                        <SideNav vertical>
                            <SideNavTitle className="text-white">
                                Metemcyber
                            </SideNavTitle>
                            <SideNavSubTitle className="text-white">
                                User
                            </SideNavSubTitle>
                            <SideNavItem>
                                <NavLink onClick={handleNav} id="/contents/account"><i className="fas fa-user"></i> Account</NavLink>
                            </SideNavItem>
                            <SideNavSubTitle className="text-white">
                                Contents
                            </SideNavSubTitle>
                            <SideNavItem>
                                <NavLink onClick={handleNav} id="/contents/buy"><i className="fas fa-ticket-alt"></i> Buy tokens</NavLink>
                            </SideNavItem>
                            <SideNavItem>
                                <NavLink onClick={handleNav} id="/contents/challange/execution"><i className="fas fa-play-circle"></i> Run challange</NavLink>
                            </SideNavItem>
                            <SideNavItem>
                                <NavLink onClick={handleNav} id="/contents/challange/cancel"><i className="fas fa-stop-circle"></i> Cancel challange</NavLink>
                            </SideNavItem>
                            <LogoutNav>
                                <NavLink onClick={handleLogout}><i className="fas fa-sign-out-alt"></i> Log out</NavLink>
                            </LogoutNav>
                        </SideNav>
                    </ColSideNav>

                    <ColNoGutter xs="10" >
                        <Row>
                            <Col xs="12">
                                <MainContent>
                                    <Switch>
                                        <Route path="/contents/account" name="account" render={props => <Account {...props} />} />
                                        <Route path="/contents/buy" name="account" render={props => <Buy {...props} />} />
                                        <Route path="/contents/challange/execution" name="challange-execution" render={props => <ChallangeExecution {...props} setChallangeInterval={setChallangeInterval} />} />
                                        <Route path="/contents/challange/cancel" name="challange-cancel" render={props => <ChallangeCancel {...props} />} />
                                        <Route path="/contents" name="account" render={props => <Account {...props} />} />
                                    </Switch>
                                </MainContent>
                            </Col>
                        </Row>
                    </ColNoGutter>
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
                        Successfully executed the challenge
                    </div>
                    <div>
                        <List type="unstyled">
                            <li>
                                Incoming URL：{challange.url}
                            </li>
                            <li>
                                Token：{challange.token}
                            </li>
                            <li>
                                Title：{challange.title}
                            </li>
                            <li>
                                Storage location：{challange.dataDir}
                            </li>
                            <li>
                                Challange token：{challange.challangeToken}
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
    background-color: #5f9ea0;
`;

export const ColSideNav = styled(Col)`
    padding-right: 0px;
`;

export const ColNoGutter = styled(Col)`
    padding: 0px;
`;

export const MainContent = styled.div`
    padding: 15px;
`;

export const SideNavTitle = styled(NavbarBrand)`
    text-align: center;
    padding: 15px;
    margin-right: 0px;
    margin-bottom: 30px;
`;
export const SideNavSubTitle = styled(NavbarBrand)`
    font-size: 17px;
    padding: 15px;
    margin-right: 0px;
    opacity: 0.8;
`;

export const SideNavItem = styled(NavItem)`
    & a:hover {
        background-color: #A9C4C5;
      }
    & a {
        color: white;
        padding-left: 25px;
    }

    font-weight: bold;
`;

export const LogoutNav = styled(NavItem)`
    & a {
        color: white;
        padding-left: 25px;
    }
    font-weight: bold;
    position: absolute;
    bottom: 0;
`;

export const UserMenuNav = styled(Nav)`
    margin-left: auto;

    & a {
        color: black;
    }
`;
