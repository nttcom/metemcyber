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

import React, { useEffect, useState, useCallback } from 'react';
import styled from 'styled-components'
import { Button, Card, CardBody, CardGroup, CardImg, Col, Container, Input, InputGroup, InputGroupAddon, List, ListInlineItem, Modal, ModalHeader, ModalBody, ModalFooter, Spinner, Row } from 'reactstrap';
import { useDropzone } from 'react-dropzone';

const { ipcRenderer } = window

ipcRenderer.on('send-log', (event, arg) => {
    console.log(arg);
});

function Login(props) {
    const [pass, setPass] = useState('');
    const [loading, setLoading] = useState(false);
    const [currentKeyName, setCurrentKeyName] = useState('');
    const [selectedKey, setSelectedKey] = useState({});
    const [keyModalToggle, setKeyModalToggle] = useState(false);
    const [errorModalToggle, setErrorModalToggle] = useState(false);
    const [errorMessage, setErrorMessage] = useState('');
    const [settingModalToggle, setSettingModalToggle] = useState(false);
    const [urlValue, setUrlValue] = useState('');
    const [setup, setSetup] = useState(true);

    const handlePassChange = (e) => {
        setPass(e.target.value)
    }

    const handleUrlChange = (e) => {
        setUrlValue(e.target.value)
    }

    const handleSubmit = () => {
        setLoading(true);
        ipcRenderer.once('login', (event, arg) => {
            if (arg.commandStatus) {
                props.history.push('/contents');
            }
            setErrorMessage(arg.message);
            setErrorModalToggle(true);
            setLoading(false);
        });
        ipcRenderer.send('login', pass);
    }

    const toggleKeyModal = (e) => {
        setSelectedKey({});
        setKeyModalToggle(!keyModalToggle);
    }

    const toggleErrorModal = (e) => {
        setErrorModalToggle(!errorModalToggle);
    }

    const toggleSettingModal = (e) => {
        setSettingModalToggle(!settingModalToggle);
    }

    const setKey = (e) => {
        ipcRenderer.sendSync('set-key', { name: selectedKey.name, path: selectedKey.path });
        setCurrentKeyName(selectedKey.name);
        setKeyModalToggle(false);
    }

    const setTransactionUrl = (e) => {
        ipcRenderer.sendSync('set-transaction-url', urlValue);
        setSettingModalToggle(false);
    }

    useEffect(() => {
        sessionStorage.setItem('imageDir', `${ipcRenderer.sendSync('get-image-dir')}metemcyber_logo.png`);
        setCurrentKeyName(ipcRenderer.sendSync('get-key'));
        setPass(ipcRenderer.sendSync('get-password'));
        setUrlValue(ipcRenderer.sendSync('get-transaction-url'));
        if (sessionStorage.getItem('init') === null) {
            ipcRenderer.send('exec-init');
            ipcRenderer.once('finish-init', (event, arg) => {
                sessionStorage.setItem('init', true);
                setSetup(false);
            });
        } else {
            setSetup(false);
        }

    }, []);

    const onDrop = useCallback(acceptedFiles => {
        console.log(acceptedFiles);
        setSelectedKey(acceptedFiles[0]);

    }, []);
    const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop });

    return (
        <div className="app flex-row align-items-center">
            {setup ?
                <LoadingContents>
                    <Spinner style={{ width: '8rem', height: '8rem' }} color="primary" />
                    <div style={{ textAlign: "center" }}>Initial setting</div>
                </LoadingContents>
                :
                <>
                    <Header className="clearfix">
                        <HeaderButton className="float-right" onClick={toggleSettingModal} size="sm">Transaction API Setting</HeaderButton>
                        <HeaderButton className="float-right" onClick={toggleKeyModal} size="sm">Import Key File</HeaderButton>
                    </Header>
                    <Container>
                        <LoginRow className="justify-content-center">
                            <Col md="8">
                                <CardGroup>
                                    <LoginCard className="p-6">
                                        <CardImg top width="100%" src={sessionStorage.getItem('imageDir')} alt="Metemcyber UI" />
                                        <CardBody>
                                            <Container>
                                                <Row>
                                                    <Col md={{ size: 12 }} className="text-center">
                                                        <p className="text-muted">Your key file</p>
                                                        <KeyFile style={{ fontSize: "12px" }} className="text-muted">{currentKeyName}</KeyFile>
                                                    </Col>
                                                </Row>
                                                <Row>
                                                    <Col md={{ size: 4, offset: 4 }}>
                                                        <InputGroup>
                                                            <Input placeholder="Enter your pass" type="password" value={pass} onChange={handlePassChange} />
                                                            <Button outline color="secondary" size="md" onClick={handleSubmit} block disabled={loading} style={{ marginTop: "10px" }}>{loading ? <Spinner color="primary" /> : "Login"}</Button>
                                                        </InputGroup>
                                                    </Col>
                                                </Row>
                                            </Container>
                                        </CardBody>
                                    </LoginCard>
                                </CardGroup>
                            </Col>
                        </LoginRow>
                    </Container>
                </>
            }
            <KeyModal isOpen={keyModalToggle} toggle={toggleKeyModal} >
                <ModalHeader toggle={toggleKeyModal}>Import Key File</ModalHeader>
                <ModalBody>
                    <DropArea {...getRootProps({ className: 'dropzone' })}>
                        <input {...getInputProps()} />
                        {
                            isDragActive ?
                                <p>Drop the files here ...</p> :
                                <p>Drag 'n' drop some files here, or click to select files</p>
                        }
                    </DropArea>
                    <SelectedFile>Selected file:{selectedKey.name}</SelectedFile>
                </ModalBody>
                <ModalFooter>
                    <Button color="primary" onClick={setKey}>OK</Button>{' '}
                    <Button color="secondary" onClick={toggleKeyModal}>Cancel</Button>
                </ModalFooter>
            </KeyModal>
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
            <Modal isOpen={settingModalToggle} toggle={toggleSettingModal} >
                <ModalBody>
                    <List>
                        <ListInlineItem>Transaction API URL</ListInlineItem>
                        <ListInlineItem>
                            <UrlInput value={urlValue} onChange={handleUrlChange} />
                        </ListInlineItem>
                    </List>
                </ModalBody>
                <ModalFooter>
                    <Button color="primary" onClick={setTransactionUrl}>OK</Button>{' '}
                    <Button color="secondary" onClick={toggleSettingModal}>Cancel</Button>
                </ModalFooter>
            </Modal>
        </div>
    );
}

export default Login;

const Header = styled.div`
    padding: .5rem;
`;

const LoginRow = styled(Row)`
    margin-top: 50px;
`;

const LoginCard = styled(Card)`
    border: 0;
`;

const KeyFile = styled.p`
    font-size: 12px;
`
const KeyModal = styled(Modal)`
    max-width: 850px;
`;

const DropArea = styled.div`
    width: 100%;
    height: 200px;
    border: 5px dashed #ccc;
    display: flex;
    align-items: center;
    justify-content: center;
`;

const SelectedFile = styled.p`
    display: block;
    margin-top: 25px;
    margin-left: 5px;
`;

const LoadingContents = styled.div`
    position: absolute; 
    top: 50%;
    left: 50%;
    transform: translateY(-50%) translateX(-50%);
`;

const UrlInput = styled(Input)`
    width: 250px;
`;

const HeaderButton = styled(Button)`
    margin: 0 5px;
`;

const ErrorParagraph = styled.p`
    color: red;
`;