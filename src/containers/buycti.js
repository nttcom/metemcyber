import React, { useEffect, useState } from 'react';
import { Button, Input, InputGroup, InputGroupAddon, List, Modal, ModalBody, ModalFooter } from 'reactstrap';
import './default.css';



function BuyCti(props) {
    const { ipcRenderer } = window;
    const [content, setContent] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [isSearch, setIsSearch] = useState(false);
    const [searchText, setSearchText] = useState("");
    const [modalToggle, setModalToggle] = useState(false);
    const [targetId, setTargetId] = useState('');

    useEffect(() => {
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
        const retValue = ipcRenderer.sendSync('select-10', ['s', searchText]);
        console.log(retValue)
        setContent(retValue);
        setIsSearch(!isSearch);
    }

    const handleRelease = () => {
        const retValue = ipcRenderer.sendSync('select-10', ['a']);
        console.log(retValue)
        setContent(retValue);
        setIsSearch(!isSearch);
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
                <div>
                    <div className="search">
                        <InputGroup>
                            <Input value={searchText} onChange={handleChange} />
                            <InputGroupAddon addonType="append">
                                <Button color="secondary" onClick={handleSearch} disabled={isSearch}>検索</Button>
                                <Button color="secondary" onClick={handleRelease} disabled={!isSearch}>解除</Button>
                            </InputGroupAddon>
                        </InputGroup>
                    </div>
                    <div className="content">
                        <List type="unstyled">
                            {content.item.map((val, idx) => {
                                return <li key={idx}>[{val.id}]{val.name}
                                    <ul>
                                        <li>Addr：{val.addr}</li>
                                        <li>UUID：{val.uuid}</li>
                                        <li>Price：{val.price}</li>
                                        <li>Remaining Token：{val.left}</li>
                                        <li><Button onClick={toggle} value={val.id}>購入</Button></li>
                                    </ul>
                                </li>
                            })}
                        </List>
                    </div>
                </div>
            }
            <Modal isOpen={modalToggle} toggle={toggle} >
                <ModalBody>
                    Are you sure you want to buy
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