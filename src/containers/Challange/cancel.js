import React, { useEffect, useState } from 'react';
import { Button, Input, InputGroup, InputGroupAddon, List, Modal, ModalBody, ModalFooter } from 'reactstrap';
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
                <div>
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
                        <List type="unstyled">
                            {content.item.map((val, idx) => {
                                return <li key={idx}>[{val.id}]{val.name}
                                    <ul>
                                        <li>Addr：{val.addr}</li>
                                        <li>State：{val.state}</li>
                                        <li><Button onClick={toggle} value={val.id}>キャンセルを実行</Button></li>
                                    </ul>
                                </li>
                            })}
                            {content.item.length === 0 && "アイテムは存在しません"}
                        </List>
                    </div>
                </div>
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
