import React, { useEffect, useState } from 'react';
import { List } from 'reactstrap';
import './default.css';



function Account(props) {
    const { ipcRenderer } = window;
    const [content, setContent] = useState([]);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        const retValue = ipcRenderer.sendSync('select-menu', '1');
        console.log(retValue);
        setContent(retValue);
        setIsLoading(false);
        return () => console.log('unmounting...');
    }, [])
    return (
        <div>
            {isLoading ?
                <div>
                    Loading...
                </div>
                :
                <List type="unstyled" className="main-content">
                    <li> サマリー
                    <ul>
                            <li>EOAアドレス：{content.summary.eoa_address}</li>
                            <li>所持ETH：{content.summary.eth_balance}</li>
                        </ul>
                    </li>
                    <li> コントラクト
                    <ul>
                            <li>カタログアドレス：{content.contract.catalog_address}</li>
                            <li>ブローカーアドレス：{content.contract.broker_address}</li>
                            <li>オペレータアドレス：{content.contract.operator_address}</li>
                        </ul>
                    </li>
                    <li> カタログ
                    <ul>
                            <li>所持ユニークCTIトークン数：{content.catalog.number_of_unique_token}</li>
                            <li>CTIトークン発行回数：{content.catalog.number_of_token_issue}</li>
                        </ul>
                    </li>
                    <li> CTIトークン
                    <ul>
                            {content.tokens.map((val, idx) => {
                                return <li key={idx}>ID:{val.id}
                                    <ul>
                                        <li>Quantity：{val.quantity}</li>
                                        <li>Addr：{val.addr}</li>
                                    </ul>
                                </li>
                            })}
                        </ul>
                    </li>
                </List>
            }
        </div >
    );
}

export default Account;