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
import { Button, Card, CardBody, CardGroup, CardImg, Col, Container, Input, InputGroup, InputGroupAddon, Modal, ModalHeader, ModalBody, ModalFooter, Spinner, Row } from 'reactstrap';
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
    const [modalToggle, setModalToggle] = useState(false);
    const [setup, setSetup] = useState(true);

    const handleChange = (e) => {
        setPass(e.target.value)
    }

    const handleSubmit = () => {
        setLoading(true);
        ipcRenderer.once('login', (event, arg) => {
            console.log(arg)
            props.history.push('/contents');
        });
        ipcRenderer.send('login', pass);
    }

    const toggle = (e) => {
        setSelectedKey({});
        setModalToggle(!modalToggle);
    }

    const handleOk = (e) => {
        ipcRenderer.sendSync('set-key', { name: selectedKey.name, path: selectedKey.path });
        setCurrentKeyName(selectedKey.name);
        setModalToggle(false);
    }

    useEffect(() => {
        sessionStorage.setItem('imageDir', `${ipcRenderer.sendSync('get-image-dir')}metemcyber_logo.png`);
        setCurrentKeyName(ipcRenderer.sendSync('get-key'));
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
                        <Button className="float-right" onClick={toggle} size="sm">Import Key File</Button>
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
                                                            <Input placeholder="Enter your pass" type="password" value={pass} onChange={handleChange} />
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
            <KeyModal isOpen={modalToggle} toggle={toggle} >
                <ModalHeader toggle={toggle}>Import Key File</ModalHeader>
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
                    <Button color="primary" onClick={handleOk}>OK</Button>{' '}
                    <Button color="secondary" onClick={toggle}>Cancel</Button>
                </ModalFooter>
            </KeyModal>
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