import React, { useEffect, useState } from 'react';
import styled from 'styled-components';
import { Button, Card, CardBody, CardHeader, Input, InputGroup, InputGroupAddon, List, ListInlineItem, Modal, ModalBody, ModalFooter } from 'reactstrap';


function BuyCti(props) {
    const { ipcRenderer } = window;
    const [content, setContent] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [searchText, setSearchText] = useState(sessionStorage.getItem('searchText'));
    const [modalToggle, setModalToggle] = useState(false);
    const [targetId, setTargetId] = useState('');

    useEffect(() => {
        console.log(sessionStorage.getItem('searchText'));
        const retValue = ipcRenderer.sendSync('select-menu', '10');
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
        const retValue = ipcRenderer.sendSync('select-10', ['s', searchText]);
        console.log(retValue)
        setContent(retValue);
    }

    const handleRelease = () => {
        sessionStorage.setItem('searchText', '');
        const retValue = ipcRenderer.sendSync('select-10', ['a']);
        console.log(retValue)
        setSearchText('');
        setContent(retValue);
    }

    const handlePurchase = (e) => {
        const retValue = ipcRenderer.sendSync('select-10', [targetId, '1']);
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
                                <BuyCard>
                                <CardHeader style={{backgroundColor: "#bbe2f1"}}><strong>{val.name}</strong></CardHeader>
                                <BuyCardBody>
                                     <TopList type="inline">
                                         <ListInlineLabel>Price</ListInlineLabel>
                                         <ListInlineItem style={{fontSize: "36px"}}>{val.price}</ListInlineItem>
                                         <ListInlineLabel>pts</ListInlineLabel>
                                     </TopList>
                                     <List type="inline">
                                         <ListInlineLabel>Remaining Token</ListInlineLabel>
                                         <ListInlineItem>{val.left}</ListInlineItem>
                                     </List>
                                     <TopList type="inline">
                                         <ListInlineLabel>Addr</ListInlineLabel>
                                         <ListInlineItem>{val.addr}</ListInlineItem>
                                     </TopList>
                                     <List type="inline">
                                         <ListInlineLabel>UUID</ListInlineLabel>
                                         <ListInlineItem>{val.uuid}</ListInlineItem>
                                     </List>
                                <Button color="primary" onClick={toggle} value={val.id}>購入</Button>
                                </BuyCardBody>
                                </BuyCard>
                            </div>})}
                            {content.item.length === 0 && "アイテムは存在しません"}
                    </div>
                </MainContent>
            }
            <Modal isOpen={modalToggle} toggle={toggle} >
                <ModalBody>
                    購入します。よろしいでしょうか？
                </ModalBody>
                <ModalFooter>
                    <Button color="primary" onClick={handlePurchase}>Purchase</Button>{' '}
                    <Button color="secondary" onClick={toggle}>Cancel</Button>
                </ModalFooter>
            </Modal>
        </div>
    );
}

export default BuyCti;

export const MainContent = styled.div`
    overflow-y: auto;
    margin-top: 30px;
`;

export const BuyCard = styled(Card)`
    margin-top: 15px;
`;

export const BuyCardBody = styled(CardBody)`
    padding-right: 0;
`;

export const TopList = styled(List)`
    margin-bottom: 0;
`;

export const ListInlineLabel = styled(ListInlineItem)`
    font-weight: bold;
`;

export const PriceListInlineLabel = styled(ListInlineLabel)`
    color: crimson;
`;

export const PriceListInlineItem = styled(ListInlineItem)`
    color: crimson;
    font-size: 32px;
    font-weight: bold;
`;
