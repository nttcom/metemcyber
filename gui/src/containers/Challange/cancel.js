import React, { useEffect, useState } from 'react';
import styled from 'styled-components';
import { Badge, Button, Card, CardHeader, CardBody, Input, InputGroup, InputGroupAddon, List, ListInlineItem, Modal, ModalBody, ModalFooter } from 'reactstrap';
import '../default.css';



function Cancel(props) {
    const { ipcRenderer } = window;
    const [content, setContent] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [searchText, setSearchText] = useState(sessionStorage.getItem('searchText'));
    const [modalToggle, setModalToggle] = useState(false);
    const [targetId, setTargetId] = useState('');

    useEffect(() => {
        console.log(sessionStorage.getItem('searchText'));
        const retValue = ipcRenderer.sendSync('select-menu', '12');
        console.log(retValue)
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
        const retValue = ipcRenderer.sendSync('select-12', ['s', searchText]);
        console.log(retValue)
        setContent(retValue);
    }

    const handleRelease = () => {
        sessionStorage.setItem('searchText', '');
        const retValue = ipcRenderer.sendSync('select-12', ['a']);
        console.log(retValue)
        setSearchText('');
        setContent(retValue);
    }

    const handleExecution = () => {
        const retValue = ipcRenderer.sendSync('select-12', [targetId]);
        console.log(retValue)
        setContent(retValue);
        setModalToggle(!modalToggle);
    }

    return (
        <div>
            {isLoading ?
                <div>
                    Loading...
                </div>
                :
                <MainContent>
                    <div className="search">
                        <InputGroup>
                            <Input value={searchText} onChange={handleChange} />
                            <InputGroupAddon addonType="append">
                                <Button color="secondary" onClick={handleSearch}>検索</Button>
                                <Button color="secondary" onClick={handleRelease}>解除</Button>
                            </InputGroupAddon>
                        </InputGroup>
                    </div>
                    <div className="content">
                        {content.item.map((val, idx) => {
                            return <div key={idx}>
                                <ChallengeCard>
                                   <ChallengeCardHeader><strong>{val.name}</strong></ChallengeCardHeader>
                                   <ChallengeCardBody>
                                        <TopList type="inline">
                                            <ListInlineLabel>Addr</ListInlineLabel>
                                            <ListInlineItem>{val.addr}</ListInlineItem>
                                        </TopList>
                                        <List type="inline">
                                            <ListInlineLabel>State</ListInlineLabel>
                                            <ListInlineItem><Badge color="warning">{val.state}</Badge></ListInlineItem>
                                        </List>
                                        <Button color="danger" onClick={toggle} value={val.id}>キャンセルを実行</Button>
                                   </ChallengeCardBody>
                                </ChallengeCard>
                            </div>})}
                            {content.item.length === 0 && "アイテムは存在しません"}
                        </div>
                </MainContent>
            }
            <Modal isOpen={modalToggle} toggle={toggle} >
                <ModalBody>
                    タスクのキャンセルをします。よろしいでしょうか？
                </ModalBody>
                <ModalFooter>
                    <Button color="primary" onClick={handleExecution}>Execute</Button>{' '}
                    <Button color="secondary" onClick={toggle}>Cancel</Button>
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
