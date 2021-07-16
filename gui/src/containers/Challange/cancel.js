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
import { Badge, Button, Card, CardHeader, CardBody, Col, Container, Input, InputGroup, InputGroupAddon, List, ListInlineItem, Modal, ModalBody, ModalFooter, Row, Spinner } from 'reactstrap';
import '../default.css';



function Cancel(props) {
    const { ipcRenderer } = window;
    const [isLoading, setIsLoading] = useState(false);
    const [searchText, setSearchText] = useState('');
    const [modalToggle, setModalToggle] = useState(false);
    const [targetId, setTargetId] = useState('');
    const [split, setSplit] = useState('12');

    useEffect(() => {
        return () => console.log('unmounting...');
    }, [])
    const toggle = (e) => {
        setTargetId(e.target.value);
        setModalToggle(!modalToggle);
    }

    const handleChange = (e) => {
        setSearchText(e.target.value);
    }

    const handleSearch = () => {
    }

    const handleRelease = () => {
        setSearchText('');
    }

    const handleExecution = async () => {
        setIsLoading(true);
        ipcRenderer.send('cancel', targetId);
        ipcRenderer.once('success-cancel', async (event, arg) => {
            console.log(arg);
            await props.refreshInfo();
            setModalToggle(!modalToggle);
        });
    }

    const handleSplit = (e) => {
        setSplit(e.currentTarget.id);
    }

    return (
        <div>
            <Container>
                <MainContent>
                    <Row>
                        <Col>
                            <div className="search">
                                <InputGroup>
                                    <Input value={searchText} onChange={handleChange} />
                                </InputGroup>
                            </div>
                        </Col>
                    </Row>
                    <Row>
                        <Col>
                            <Button color="link" onClick={handleRelease}>Reset search</Button>
                        </Col>
                        <Col>
                            <Button outline color="secondary float-right" onClick={handleSplit} id="12"><i className="fas fa-list"></i></Button>
                            <Button outline color="secondary float-right" onClick={handleSplit} id="6"><i className="fas fa-table"></i></Button>
                        </Col>
                    </Row>
                    <Row>
                        <Col>
                            <div className="content">
                                <Row>
                                    {props.content.item.map((val, idx) => {
                                        if (val.name.indexOf(searchText) > -1) {
                                            return <Col xs={split} key={idx}>
                                                <div key={idx}>
                                                    <ChallengeCard>
                                                        <ChallengeCardHeader><strong>{val.name}</strong></ChallengeCardHeader>
                                                        <ChallengeCardBody>
                                                            <TopList type="inline">
                                                                <ListInlineLabel>Addr</ListInlineLabel>
                                                                <ListInlineItem>{val.addr.length > 50 && split === "6" ? `${val.addr.slice(50)}...` : val.addr}</ListInlineItem>
                                                            </TopList>
                                                            <List type="inline">
                                                                <ListInlineLabel>State</ListInlineLabel>
                                                                <ListInlineItem><Badge color="warning">{val.status}</Badge></ListInlineItem>
                                                            </List>
                                                            <Button color="danger" onClick={toggle} value={val.id}>Run cancel</Button>
                                                        </ChallengeCardBody>
                                                    </ChallengeCard>
                                                </div>
                                            </Col>
                                        }
                                    })}
                                    {props.content.item.length === 0 && "Item does not exist"}
                                </Row>
                            </div>
                        </Col>
                    </Row>
                </MainContent>
            </Container>
            <Modal isOpen={modalToggle} toggle={toggle} >
                <ModalBody>
                    Are you sure you want to run cancel?
                </ModalBody>
                <ModalFooter>
                    <Button color="primary" onClick={handleExecution} disabled={isLoading} >{isLoading ? <Spinner color="secondary" /> : "OK"}</Button>{' '}
                    <Button color="secondary" onClick={toggle} disabled={isLoading} >Cancel</Button>
                </ModalFooter>
            </Modal>
        </div>
    );
}

export default Cancel;

export const MainContent = styled.div`
    overflow-y: auto;
    margin-top: 30px;
`;

export const ChallengeCard = styled(Card)`
    margin-top: 15px;
`;

export const ChallengeCardBody = styled(CardBody)`
    padding-right: 0;
`;

export const ChallengeCardHeader = styled(CardHeader)`
    background-color: #e6bfb2;;
`;

export const ListInlineLabel = styled(ListInlineItem)`
    font-weight: bold;
`;

export const TopList = styled(List)`
    margin-bottom: 0;
`;
