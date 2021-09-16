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
import { Button, Card, CardHeader, CardBody, CardTitle, Col, Container, Input, InputGroup, List, ListInlineItem, Spinner, Row, Table, Tooltip } from 'reactstrap';
import HeatMap from 'react-heatmap-grid';


function Account(props) {
    const { ipcRenderer } = window
    const [data, setData] = useState([]);
    const [dates, setDates] = useState([]);
    const [totalContribution, setTotalContribution] = useState(0);
    const [xLabels, setXLabels] = useState([]);
    const [targetEoa, setTargetEoa] = useState(props.content.summary.eoa_address);
    const [isLoading, setIsLoading] = useState(true);

    const yLabels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const monthList = { 0: 'Jan', 1: 'Feb', 2: 'Mar', 3: 'Apr', 4: 'May', 5: 'Jun', 6: 'Jul', 7: 'Aug', 8: 'Sep', 9: 'Oct', 10: 'Nov', 11: 'Dec' }

    useEffect(() => {
        //get transaction data
        const currentDate = new Date();
        const utcEndDate = new Date(currentDate.getFullYear(), currentDate.getMonth(), currentDate.getDate() - 1);
        const utcStartDate = new Date(utcEndDate.getFullYear() - 1, utcEndDate.getMonth(), utcEndDate.getDate() + 1);

        ipcRenderer.send('get-transaction',
            {
                address: [props.content.summary.eoa_address],
                startYear: utcStartDate.getFullYear(),
                startMonth: utcStartDate.getMonth() + 1,
                startDate: utcStartDate.getDate(),
                endYear: utcEndDate.getFullYear(),
                endMonth: utcEndDate.getMonth() + 1,
                endDate: utcEndDate.getDate(),
            });

        ipcRenderer.once('send-transaction', (event, arg) => {
            console.log(arg)
            setTransaction(arg.activities);
            setIsLoading(false);
        });

        return () => console.log('unmounting...');
    }, [])


    const handleChange = (e) => {
        setTargetEoa(e.target.value);
    }

    const getTransaction = () => {
        setIsLoading(true);
        const currentDate = new Date();
        const utcEndDate = new Date(currentDate.getFullYear(), currentDate.getMonth(), currentDate.getDate() - 1);
        const utcStartDate = new Date(utcEndDate.getFullYear() - 1, utcEndDate.getMonth(), utcEndDate.getDate() + 1);

        let eoaList = [];
        if (targetEoa !== '') {
            eoaList = targetEoa.replace(' ', '').split(',');
        }
        ipcRenderer.send('get-transaction',
            {
                address: eoaList,
                startYear: utcStartDate.getFullYear(),
                startMonth: utcStartDate.getMonth() + 1,
                startDate: utcStartDate.getDate(),
                endYear: utcEndDate.getFullYear(),
                endMonth: utcEndDate.getMonth() + 1,
                endDate: utcEndDate.getDate(),
            });
        ipcRenderer.once('send-transaction', (event, arg) => {
            console.log(arg)
            setTransaction(arg.activities);
            setIsLoading(false);
        });

    }

    const setTransaction = (activities) => {
        const data = new Array(yLabels.length)
            .fill(0)
            .map(() => new Array());
        const resultDate = new Array(yLabels.length)
            .fill(0)
            .map(() => new Array());

        const xlb = [];

        let offsetCount = 0;
        let countContribution = 0;

        const currentDate = new Date();
        const endDate = new Date(currentDate.getFullYear(), currentDate.getMonth(), currentDate.getDate());
        const startDate = new Date(endDate.getFullYear() - 1, endDate.getMonth(), endDate.getDate() + 1);

        const yearDates = (endDate - startDate) / 86400000 + 1; // 86400000 is Milliseconds for one day

        // Set the '-1' in the cell of last year's part
        for (let i = 0; i < startDate.getDay(); i++) {
            data[i].push(-1);
            resultDate[i].push(new Date())
        }

        let targetDate = startDate;
        let monthNum = targetDate.getMonth();
        let month = monthList[monthNum];
        for (let i = 0; i < yearDates; i++) {
            const targetMonth = targetDate.getMonth();
            if (monthNum !== targetMonth) {
                monthNum = targetMonth;
                month = monthList[monthNum];
            }

            const day = targetDate.getDay();

            let count = 0;
            for (let val of activities) {
                if (val["days-offset"] === offsetCount) {
                    count = val.count;
                    countContribution += count;
                    break;
                }
            }

            data[day].push(count);
            resultDate[day].push(`${targetDate.getFullYear()}/${targetDate.getMonth() + 1}/${targetDate.getDate()}`);

            if (day === 0 || offsetCount === 0) {
                xlb.push(month);
                month = '';
            }

            offsetCount++;
            targetDate = new Date(targetDate.getFullYear(), targetDate.getMonth(), targetDate.getDate() + 1);
        }

        setTotalContribution(countContribution);

        setXLabels(xlb);
        setData(data);
        setDates(resultDate);
    }

    return (
        <div>
            <MainContent>
                <Card>
                    <CardHeader>Contribution</CardHeader>
                    <CardBody>
                        <AccountCardTitle>{totalContribution} contributions in {new Date().getFullYear()}</AccountCardTitle>
                        {isLoading ?
                            <Spinner color="primary" />
                            :
                            <HeatMap
                                xLabels={xLabels}
                                yLabels={yLabels}
                                data={data}
                                height={20}
                                cellStyle={(background, value, min, max, data, x, y) => (
                                    {
                                        background: `rgba(66, 86, 244, ${1 - (max - value) / (max - min)})`,
                                        border: `solid ${value !== undefined && value > -1 ? "1px" : "0px"} rgba(192, 192, 192,0.25)`,
                                        borderRadius: "3px",
                                        fontSize: "11px",
                                    })}
                                title={(value, unit, x, y) => {
                                    if (value > -1) {
                                        return `${dates[y][x]} ${value} contributions`
                                    }
                                }}
                            />
                        }
                        <AccountCardTitle>Displayed EOA address</AccountCardTitle>
                        <AccountList type="inline">
                            <InputGroup>
                                <Input value={targetEoa} onChange={handleChange} placeholder="Please enter the EOA address..." />
                            </InputGroup>
                            <Button color="primary" onClick={getTransaction}>Change EOA address</Button>
                        </AccountList>
                    </CardBody>
                </Card>
                <Card>
                    <CardHeader>Account Information</CardHeader>
                    <CardBody>
                        <AccountCardTitle>Summary</AccountCardTitle>
                        <AccountList type="inline">
                            <ListInlineLabel>EOA address</ListInlineLabel>
                            <ListInlineItem>{props.content.summary.eoa_address}</ListInlineItem>
                        </AccountList>
                        <AccountList type="inline">
                            <ListInlineLabel>ETH</ListInlineLabel>
                            <ListInlineItem>{props.content.summary.eth_balance}</ListInlineItem>
                        </AccountList>
                        <hr />
                        <AccountCardTitle>Contract</AccountCardTitle>
                        <AccountList type="inline">
                            <ListInlineLabel>Catalog address(actives)</ListInlineLabel>
                            <ListInlineItem>{props.content.contract.catalog_address_actives}</ListInlineItem>
                        </AccountList>
                        <AccountList type="inline">
                            <ListInlineLabel>Catalog address(reserves)</ListInlineLabel>
                            <ListInlineItem>{props.content.contract.catalog_address_reserves}</ListInlineItem>
                        </AccountList>
                        <AccountList type="inline">
                            <ListInlineLabel>Broker address</ListInlineLabel>
                            <ListInlineItem>{props.content.contract.broker_address}</ListInlineItem>
                        </AccountList>
                        <AccountList type="inline">
                            <ListInlineLabel>Operator address</ListInlineLabel>
                            <ListInlineItem>{props.content.contract.operator_address}</ListInlineItem>
                        </AccountList>
                        <hr />
                        <AccountCardTitle>Catalog</AccountCardTitle>
                        <AccountList type="inline">
                            <ListInlineLabel>Number of unique CTI token</ListInlineLabel>
                            <ListInlineItem>{props.content.catalog.number_of_unique_token}</ListInlineItem>
                            <ListInlineLabel style={{ marginLeft: "30px" }}>CTI Token issuance count</ListInlineLabel>
                            <ListInlineItem>{props.content.catalog.number_of_token_issue}</ListInlineItem>
                        </AccountList>
                        <hr />
                        <AccountCardTitle>CTI token</AccountCardTitle>
                        {props.content.tokens.map((val, idx) => {
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
