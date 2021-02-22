import React, { useState } from 'react';
import { Alert, Button, Card, CardTitle, CardBody, CardGroup, Col, Container, Form, FormFeedback, FormGroup, Label, Input, InputGroup, InputGroupAddon, InputGroupText, Modal, ModalHeader, ModalBody, ModalFooter, Spinner, Row } from 'reactstrap';
import './login.css';

function Login(props) {
    const { ipcRenderer } = window
    const [pass, setPass] = useState('');
    const [loading, setLoading] = useState(false);

    const handleChange = (e) => {
        console.log(window.location.href);
        setPass(e.target.value)
    }

    const handleSubmit = () => {
        
        setLoading(true);
        ipcRenderer.on('login', (event, arg) => {
            console.log(arg) 
            props.history.push('/contents')
        });
        ipcRenderer.send('login', pass)
        
        //props.history.push('/overview')
    }

    return (
        <div className="app flex-row align-items-center">
            <Container>
                <Row className="justify-content-center">
                    <Col md="5">
                        <CardGroup>
                            <Card className="p-4">
                                <CardTitle tag="h3">Metemcyber GUI</CardTitle>
                                <CardBody>
                                    <InputGroup>
                                        <InputGroupAddon addonType="prepend">
                                        </InputGroupAddon>
                                        <Input placeholder="password" type="password" value={pass} onChange={handleChange} />
                                    </InputGroup>
                                    <Button outline color="secondary" onClick={handleSubmit}>login{loading && <Spinner color="primary" />}</Button>
                                </CardBody>
                            </Card>
                        </CardGroup>
                    </Col>
                </Row>
            </Container>
        </div>
    );
}

export default Login;