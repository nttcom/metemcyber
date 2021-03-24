import React, { useState } from 'react';
import styled from 'styled-components'
import { Alert, Button, Card, CardTitle, CardBody, CardGroup, CardImg, Col, Container, Form, FormFeedback, FormGroup, Label, Input, InputGroup, InputGroupAddon, InputGroupText, Media, Modal, ModalHeader, ModalBody, ModalFooter, Spinner, Row } from 'reactstrap';

function Login(props) {
    const { ipcRenderer } = window
    const [pass, setPass] = useState('');
    const [loading, setLoading] = useState(false);

    const handleChange = (e) => {
        setPass(e.target.value)
    }

    const handleSubmit = () => {
        setLoading(true);
        ipcRenderer.on('login', (event, arg) => {
            console.log(arg) 
            props.history.push('/contents')
        });
        ipcRenderer.send('login', pass)
    }

    ipcRenderer.on('send-log', (event, arg) => {
        console.log(arg);
    });

    return (
        <div className="app flex-row align-items-center">
            <Container>
                <LoginRow className="justify-content-center">
                    <Col md="4">
                        <CardGroup>
                            <LoginCard className="p-4">
                                <CardImg top width="100%" src="./metemcyber_logo.png" alt="Metemcyber UI" />
                                <CardBody>
                                    <InputGroup style={{marginBottom: "10px"}}>
                                        <InputGroupAddon addonType="prepend">
                                        </InputGroupAddon>
                                        <Input placeholder="Enter your pass" type="password" value={pass} onChange={handleChange} />
                                    </InputGroup>
                                    <Button outline color="secondary" size="md" onClick={handleSubmit} block>Login{loading && <Spinner color="primary" />}</Button>
                                </CardBody>
                            </LoginCard>
                        </CardGroup>
                    </Col>
                </LoginRow>
            </Container>
        </div>
    );
}

export default Login;

const LoginRow = styled(Row)`
    margin-top: 10px;
`;

const LoginCard = styled(Card)`
    border: 0;
`;
