import React, { useEffect, useState } from 'react';
import styled from 'styled-components';
import { Button, Card, CardHeader, CardBody, Col, Container, Input, InputGroup, InputGroupAddon, List, ListInlineItem, Modal, ModalBody, ModalFooter, Row } from 'reactstrap';
import '..//default.css';


function Execution(props) {
    const { ipcRenderer } = window;
    const [content, setContent] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [searchText, setSearchText] = useState(sessionStorage.getItem('searchText'));
    const [modalToggle, setModalToggle] = useState(false);
    const [targetId, setTargetId] = useState('');
    const [split, setSplit] = useState('12');

    useEffect(() => {
        const retValue = ipcRenderer.sendSync('select-menu', '11');
        setContent(retValue);
        setIsLoading(false);
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
        sessionStorage.setItem('searchText', searchText);
        const retValue = ipcRenderer.sendSync('select-11', ['s', searchText]);
        console.log(retValue)
        setContent(retValue);
    }

    const handleRelease = () => {
        sessionStorage.setItem('searchText', '');
        const retValue = ipcRenderer.sendSync('select-11', ['a']);
        console.log(retValue)
        setSearchText('');
        setContent(retValue);
    }

    const handleExecution = () => {
        const retValue = ipcRenderer.sendSync('select-11', [targetId]);
        console.log(retValue)
        sessionStorage.setItem('challange', true);
        setContent(retValue);
        setModalToggle(!modalToggle);
        props.setChallangeInterval();
    }

    const handleSplit = (e) => {
        setSplit(e.currentTarget.id);
    }

    return (
        <div>
            {isLoading ?
                <div>
                    Loading...
                </div>
                :
                <Container>
                    <MainContent>
                        <Row>
                            <Col>
                                <div className="search">
                                    <InputGroup>
                                        <Input value={searchText} onChange={handleChange} />
                                        <InputGroupAddon addonType="append">
                                            <Button color="secondary" onClick={handleSearch}><i className="fas fa-search"></i></Button>
                                        </InputGroupAddon>
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
                                        {content.item.map((val, idx) => {
                                            return <Col xs={split} key={idx}>
                                                <div key={idx}>
                                                    <ChallengeCard>
                                                        <ChallengeCardHeader><strong>{val.name}</strong></ChallengeCardHeader>
                                                        <ChallengeCardBody>
                                                            <TopList type="inline">
                                                                <ListInlineLabel>Price</ListInlineLabel>
                                                                <ListInlineItem style={{ fontSize: "36px" }}>{val.price}</ListInlineItem>
                                                                <ListInlineLabel>pts</ListInlineLabel>
                                                            </TopList>
                                                            <List type="inline">
                                                                <ListInlineLabel>Remaining Token</ListInlineLabel>
                                                                <ListInlineItem>{val.left}</ListInlineItem>
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
                                        })}
                                        {content.item.length === 0 && "Item does not exist"}
                                    </Row>
                                </div>
                            </Col>
                        </Row>
                    </MainContent>
                </Container>
            }
            <Modal isOpen={modalToggle} toggle={toggle} >
                <ModalBody>
                    Are you sure you want to run challenge?
                </ModalBody>
                <ModalFooter>
                    <Button color="primary" onClick={handleExecution}>OK</Button>{' '}
                    <Button color="secondary" onClick={toggle}>Cancel</Button>
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

