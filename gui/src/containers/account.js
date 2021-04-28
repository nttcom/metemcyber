import React, { useEffect, useState } from 'react';
import styled from 'styled-components';
import { Card, CardHeader, CardBody, CardTitle, Col, Container, List, ListInlineItem, Row, Table } from 'reactstrap';


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
                <MainContent>
                    <Card>
                        <CardHeader>Account Information</CardHeader>
                        <CardBody>
                            <AccountCardTitle>Summary</AccountCardTitle>
                            <AccountList type="inline">
                                <ListInlineLabel>EOA address</ListInlineLabel>
                                <ListInlineItem>{content.summary.eoa_address}</ListInlineItem>
                            </AccountList>
                            <AccountList type="inline">
                                <ListInlineLabel>ETH</ListInlineLabel>
                                <ListInlineItem>{content.summary.eth_balance}</ListInlineItem>
                            </AccountList>
                            <hr />
                            <AccountCardTitle>Contract</AccountCardTitle>
                            <AccountList type="inline">
                                <ListInlineLabel>Catalog address</ListInlineLabel>
                                <ListInlineItem>{content.contract.catalog_address}</ListInlineItem>
                            </AccountList>
                            <AccountList type="inline">
                                <ListInlineLabel>Broker address</ListInlineLabel>
                                <ListInlineItem>{content.contract.broker_address}</ListInlineItem>
                            </AccountList>
                            <AccountList type="inline">
                                <ListInlineLabel>Operator address</ListInlineLabel>
                                <ListInlineItem>{content.contract.operator_address}</ListInlineItem>
                            </AccountList>
                            <hr />
                            <AccountCardTitle>Catalog</AccountCardTitle>
                            <AccountList type="inline">
                                <ListInlineLabel>Number of unique CTI token</ListInlineLabel>
                                <ListInlineItem>{content.catalog.number_of_unique_token}</ListInlineItem>
                                <ListInlineLabel style={{ marginLeft: "30px" }}>CTI Token issuance count</ListInlineLabel>
                                <ListInlineItem>{content.catalog.number_of_token_issue}</ListInlineItem>
                            </AccountList>
                            <hr />
                            <AccountCardTitle>CTI token</AccountCardTitle>
                            {content.tokens.map((val, idx) => {
                                return <AccountList type="inline" key={idx}>
                                    <CTIListLabel>Quantity:</CTIListLabel>
                                    <ListInlineItem>{val.quantity}</ListInlineItem>
                                    <CTIListLabel>Addr:</CTIListLabel>
                                    <ListInlineItem>{val.addr}</ListInlineItem>
                                </AccountList>
                            })}
                        </CardBody>
                    </Card>
                </MainContent>
            }
        </div>
    );
}

export default Account;

export const MainContent = styled.div`
    overflow-y: auto;
    margin-top: 30px;
`;

export const AccountList = styled(List)`
    margin-bottom: 2px;
`;

export const AccountCardTitle = styled(CardTitle)`
    margin-top: 15px;
    font-weight: bold;
`;

export const ListInlineLabel = styled(ListInlineItem)`
    font-weight: bold;
    width: 220px;
`;

export const CTIListLabel = styled(ListInlineItem)`
    width: 80px;
    font-weight: bold;
    margin-left: 30px;
`;
