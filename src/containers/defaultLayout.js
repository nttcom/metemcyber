import React, { useState } from 'react';
import { List, Nav, NavItem, NavLink } from 'reactstrap';
import './default.css';



function DefaultLayout(props) {
    const { ipcRenderer } = window
    const [content, setContent] = useState([]);

    const handleAccount = () => {
        const retValue = ipcRenderer.sendSync('select-menu', '1');
        console.log(retValue);
        setContent(retValue);
    }

    const handleLogout = () => {
        const retValue = ipcRenderer.sendSync('select-logout');
        console.log(retValue)
        props.history.push('/');
    }

    return (
        <div>
            <Nav className="header-nav">
                <NavItem>
                    <NavLink onClick={handleAccount}>Account</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink onClick={handleLogout}>Logout</NavLink>
                </NavItem>
            </Nav>
            <Nav vertical className="side-nav">
                <NavItem>
                    <NavLink disabled href="#">CTIトークンの購入</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">チャレンジの実行</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">タスク(チャレンジ)のキャンセル</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">保有トークンの廃棄</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">新規CTIトークンの配布</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">チャレンジの受付開始・解除</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">発行トークンの追加委託・引取・登録取消</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">ローカルMISPデータからのCTIトークン自動配布</NavLink>
                </NavItem>
                <NavItem>
                    <NavLink disabled href="#">CTIトークンのパラメータ変更</NavLink>
                </NavItem>
            </Nav>
            <List type="unstyled" className="main-content">
                {
                    content.map((val, idx) => {
                        return <li key={idx}>{val}</li>
                    })
                }
            </List>
        </div>
    );
}

export default DefaultLayout;