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

import React, { useEffect, useState } from 'react';
import styled from 'styled-components';
import { Badge, Button, Col, Row, Collapse, Container, Navbar, NavbarToggler, NavbarBrand, UncontrolledDropdown, DropdownToggle, DropdownMenu, DropdownItem, NavbarText, List, ListInlineItem, Modal, ModalHeader, ModalBody, ModalFooter, Nav, NavItem, NavLink, Spinner, Toast, ToastBody, ToastHeader } from 'reactstrap';
import { Route, Switch } from 'react-router-dom';
import Account from './account';
import Buy from './buycti';
import ChallangeExecution from './Challange/execution';
import ChallangeCancel from './Challange/cancel';

function DefaultLayout(props) {
    const { ipcRenderer } = window
    const [intervalId, setIntervalId] = useState(0);
    const [toastOpen, setToastOpen] = useState(false);
    const [challangeResulst, setChallangeResult] = useState({});
    const [isLoading, setIsLoading] = useState(true);
    const [accountInfo, setAccountInfo] = useState([]);
    const [tokenList, setTokenList] = useState([]);
    const [challangeList, setChallangeList] = useState([]);
    const [seekerStatus, setSeekerStatus] = useState(false);
    const [errorModalToggle, setErrorModalToggle] = useState(false);
    const [errorMessage, setErrorMessage] = useState('');

    useEffect(async () => {
        const result = await Promise.all(getInfo())
            .catch((message) => {
                setErrorMessage(message)
                setErrorModalToggle(true);
                return false;
            });

        if (!result) {
            return;
        }

        setInfoInterval();
        setIsLoading(false);
    }, []);

    const setInfoInterval = () => {
        const id = setInterval(async () => {
            await Promise.all(getInfo())
                .catch((message) => {
                    setErrorMessage(message)
                    setErrorModalToggle(true);
                });
        }, 30000);
        setIntervalId(id);
    };

    const refreshInfo = async () => {
        clearInterval(intervalId);
        await Promise.all(getInfo())
            .catch((message) => {
                setErrorMessage(message)
                setErrorModalToggle(true);
            });
        setInfoInterval();
    };

    const getInfo = () => {
        return [
            new Promise((resolve, reject) => {
                ipcRenderer.send('account');
                ipcRenderer.once('send-accountinfo', (event, arg) => {
                    console.log(arg)

                    if (!arg.commandStatus) {
                        reject(arg.message);
                        return;
                    }

                    setAccountInfo(arg.data.accountInfo);
                    resolve(true);
                });
            }),
            new Promise((resolve, reject) => {
                ipcRenderer.send('token');
                ipcRenderer.once('send-tokenlist', (event, arg) => {
                    console.log(arg)

                    if (!arg.commandStatus) {
                        reject(arg.message);
                        return;
                    }

                    setTokenList(arg.data.tokenList);
                    resolve();
                });
            }),
            new Promise((resolve, reject) => {
                ipcRenderer.send('seeker');
                ipcRenderer.once('send-seekerstatus', (event, arg) => {
                    console.log(arg)

                    if (!arg.commandStatus) {
                        reject(arg.message);
                        return;
                    }

                    setSeekerStatus(arg.data.seekerStatus);
                    resolve();
                });
            }),
            new Promise((resolve, reject) => {
                ipcRenderer.send('challange');
                ipcRenderer.once('send-challangeList', (event, arg) => {
                    console.log(arg)

                    if (!arg.commandStatus) {
                        reject(arg.message);
                        return;
                    }

                    setChallangeList(arg.data.challangeList);
                    resolve();
                });
            })
        ];
    };

    const handleLogout = () => {
        clearInterval(intervalId);
        ipcRenderer.sendSync('logout');
        props.history.push('/');
    }

    const toastToggle = () => {
        setToastOpen(false);
    }

    const handleNav = (e) => {
        props.history.push(e.target.id);
    }

    const openDownloadDir = () => {
        ipcRenderer.sendSync('open-download-dir');
    }

    const toggleErrorModal = () => {
        setErrorModalToggle(!errorModalToggle);
        if (isLoading) {
            props.history.push('/login');
        }
    }

    return (
        <div>
            {isLoading ?
                <LoadingContents>
                    <Spinner style={{ width: '8rem', height: '8rem' }} color="primary" />
                    <div style={{ textAlign: "center" }}>Getting information</div>
                </LoadingContents>
                :
                <Container fluid style={{ paddingLeft: "0px" }}>
                    <Row>
                        <ColSideNav xs="2">
                            <SideNav vertical>
                                <SideNavTitle className="text-white">
                                    Metemcyber
                                </SideNavTitle>
                                <SideNavStatus>
                                    <p className="title">Seeker:</p><Badge color={seekerStatus ? "success" : "danger"}>{seekerStatus ? "Running" : "Stop"}</Badge>
                                </SideNavStatus>
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
                        <ColNoGutter>
                            <Row>
                                <Col xs="12">
                                    <MainContent>
                                        <Switch>
                                            <Route path="/contents/account" name="account" render={() => <Account {...props} content={accountInfo} />} />
                                            <Route path="/contents/buy" name="token-buy" render={() => <Buy {...props} content={tokenList} refreshInfo={refreshInfo} />} />
                                            <Route path="/contents/challange/execution" name="challange-execution" render={() => <ChallangeExecution {...props} accountInfo={accountInfo} tokenList={tokenList} setChallangeResult={setChallangeResult} setToastOpen={setToastOpen} refreshInfo={refreshInfo} />} />
                                            <Route path="/contents/challange/cancel" name="challange-cancel" render={() => <ChallangeCancel {...props} content={challangeList} refreshInfo={refreshInfo} />} />
                                            <Route path="/contents" name="account" render={() => <Account {...props} content={accountInfo} />} />
                                        </Switch>
                                    </MainContent>
                                </Col>
                            </Row>
                        </ColNoGutter>
                    </Row>
                </Container>
            }
            <Toast
                style={{
                    position: 'fixed',
                    zIndex: 100,
                    right: 10,
                    bottom: 10,
                    minWidth: "600px",
                    maxWidth: "800px"
                }}
                isOpen={toastOpen}>
                <ToastHeader toggle={toastToggle} icon="success">Successfully executed the challenge</ToastHeader>
                <ToastBody>
                    <List type="inline">
                        <ListInlineLabel>Title</ListInlineLabel>
                        <ListInlineItem>{challangeResulst.name}(ID:{challangeResulst.id})</ListInlineItem>
                    </List>
                    <List type="inline">
                        <ListInlineLabel>Downloaded file name</ListInlineLabel>
                        <ListInlineItem>{challangeResulst.jsonName}</ListInlineItem>
                    </List>
                    <Button color="secondary" onClick={openDownloadDir}>Open download directory</Button>
                </ToastBody>
            </Toast>
            <Modal isOpen={errorModalToggle} toggle={toggleErrorModal} >
                <ModalHeader >Error</ModalHeader>
                <ModalBody>
                    <p>An error has occurred.</p>
                    <ErrorParagraph>{errorMessage}</ErrorParagraph>
                </ModalBody>
                <ModalFooter>
                    <Button color="primary" onClick={toggleErrorModal}>OK</Button>{' '}
                </ModalFooter>
            </Modal>
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
    min-width: 220px;
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
`;
export const SideNavSubTitle = styled(NavbarBrand)`
    font-size: 17px;
    padding: 15px;
    margin-right: 0px;
    opacity: 0.8;
`;

export const SideNavStatus = styled.div`
    font-size: 16px;
    color: white;
    padding: 15px;
    margin-right: 0px;
    opacity: 0.8;
    & p {
        display:inline;
    }
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

export const LoadingContents = styled.div`
    position: absolute; 
    top: 50%;
    left: 50%;
    transform: translateY(-50%) translateX(-50%);
`;

export const ListInlineLabel = styled(ListInlineItem)`
    font-weight: bold;
`;

export const ErrorParagraph = styled.p`
    color: red;
`;