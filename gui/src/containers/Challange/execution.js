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
import { Button, Card, CardHeader, CardBody, Col, Container, Input, InputGroup, InputGroupAddon, List, ListInlineItem, Modal, ModalBody, ModalFooter, Row, Spinner } from 'reactstrap';
import '..//default.css';

function Execution(props) {
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

    const handleRelease = () => {
        setSearchText('');
    }

    const handleExecution = () => {
        setIsLoading(true);
        ipcRenderer.send('challange-start', `${targetId}`);
        ipcRenderer.once('success-challange-start', async (event, arg) => {
            console.log(arg);
            console.log("success-challange-start")
            await new Promise(resolve => setTimeout(resolve, 2000))
            await props.refreshInfo();
            setIsLoading(false);
            setModalToggle(!modalToggle);
        });
        ipcRenderer.once('success-challange-result', async (event, arg) => {
            console.log(arg);
            console.log("success-challange-result")
            props.setChallangeResult(arg);
            props.setToastOpen(true);
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
                                    <Input value={searchText} onChange={handleChange} placeholder="Search for token title..." />
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
                                    {props.accountInfo.tokens.map((token, idx) => {
                                        for (let val of props.tokenList.item) {
                                            if (token.addr === val.addr && val.name.indexOf(searchText) > -1) {
                                                return <Col xs={split} key={idx}>
                                                    <div key={idx}>
                                                        <ChallengeCard>
                                                            <ChallengeCardHeader><strong>{val.name}</strong></ChallengeCardHeader>
                                                            <ChallengeCardBody>
                                                                <List type="inline">
                                                                    <ListInlineLabel>Remaining Token</ListInlineLabel>
                                                                    <ListInlineItem>{token.quantity}</ListInlineItem>
                                                                </List>
                                                                <TopList type="inline">
                                                                    <ListInlineLabel>Addr</ListInlineLabel>
                                                                    <ListInlineItem>{val.addr.length > 50 && split === "6" ? `${val.addr.slice(50)}...` : val.addr}</ListInlineItem>
                                                                </TopList>
                                                                <List type="inline">
                                                                    <ListInlineLabel>UUID</ListInlineLabel>
                                                                    <ListInlineItem>{val.uuid.length > 50 && split === "6" ? `${val.uuid.slice(50)}...` : val.uuid}</ListInlineItem>
                                                                </List>
                                                                <Button color="success" onClick={toggle} value={val.id}>Run challange</Button>
                                                            </ChallengeCardBody>
                                                        </ChallengeCard>
                                                    </div>
                                                </Col>
                                            }
                                        }
                                    })}
                                    {props.accountInfo.tokens.length === 0 && "Item does not exist"}
                                </Row>
                            </div>
                        </Col>
                    </Row>
                </MainContent>
            </Container>
            <Modal isOpen={modalToggle} toggle={toggle} >
                <ModalBody>
                    Are you sure you want to run challenge?
                </ModalBody>
                <ModalFooter>
                    <Button color="primary" onClick={handleExecution} disabled={isLoading}>{isLoading ? <Spinner color="secondary" /> : "OK"}</Button>{' '}
                    <Button color="secondary" onClick={toggle} disabled={isLoading}>Cancel</Button>
                </ModalFooter>
            </Modal>
        </div>
    );
}

export default Execution;

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

export const TopList = styled(List)`
    margin-bottom: 0;
`;

export const ListInlineLabel = styled(ListInlineItem)`
    font-weight: bold;
`;

export const ChallengeListInlineLabel = styled(ListInlineLabel)`
    color: crimson;
`;

export const ChallengeListInlineItem = styled(ListInlineItem)`
    color: crimson;
    font-size: 32px;
    font-weight: bold;
`;

export const ChallengeCardHeader = styled(CardHeader)`
    background-color: #bee0c2;
`;

