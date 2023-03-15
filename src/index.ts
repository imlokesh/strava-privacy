#!/usr/bin/env node

import { Browser, chromium, Page } from 'playwright';
import winston from 'winston';
import * as fs from 'fs';
import { Context } from 'vm';
import { Command } from 'commander'
import ngork from 'ngrok';
import express from 'express';
import axios from 'axios';
import { randomUUID } from 'crypto';
import formData from 'form-data';
import { exit } from 'process';
import inquirer from 'inquirer';
import tablePrompt from 'inquirer-table-prompt';

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
        winston.format.printf((info) => `${info.timestamp} [${info.level}] - ${info.message}`)),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: './strava-privacy.log' })
    ],
});

inquirer.registerPrompt("table", tablePrompt);

let browser: Browser | undefined, context: Context | undefined, page: Page;

const ACTIVITY_TYPES = ["AlpineSki", "BackcountrySki", "Canoeing", "Crossfit", "EBikeRide", "Elliptical", "Golf", "Handcycle", "Hike", "IceSkate", "InlineSkate", "Kayaking", "Kitesurf", "NordicSki", "Ride", "RockClimbing", "RollerSki", "Rowing", "Run", "Sail", "Skateboard", "Snowboard", "Snowshoe", "Soccer", "StairStepper", "StandUpPaddling", "Surfing", "Swim", "Velomobile", "VirtualRide", "VirtualRun", "Walk", "WeightTraining", "Wheelchair", "Windsurf", "Workout", "Yoga"];
const ACTIVITY_VISIBILITY_TYPES = ["everyone", "followers_only", "only_me"];

const program = new Command();

program
    .option("--strava-email <value>", "Strave login email address. ")
    .option("--strava-password <value>", "Strava login password. ")
    .option("--ngrok-auth <value>", "Ngrok auth token. ")
    .option("--port <value>", "Port for webhook client. ", "8095")
    .option("--num <value>", "Number of activities to process. ")
    .option("--rules <values...>", "Rules to be used to set privacy on activities. ")
    .option("--watch", "Watch for new activities. ")
    .option("--headful", "Run chromium in non-headless mode. ");

interface User {
    expires_at?: number,
    refresh_token?: string,
    access_token?: string,
    client_id?: string,
    client_secret?: string,
    email?: string,
    password?: string
}

let user: User = {};

program.parse(process.argv);
const options = program.opts();

if (options.stravaEmail) user.email = options.stravaEmail;
if (options.stravaPassword) user.password = options.stravaPassword;

let maxActivitiesToCheck: number = parseInt(options.num) || 0;
const port: number = parseInt(options.port) || 8095;

let ngrokAuth = options.ngrokAuth;

const rulesDef: string[] = options.rules;
const rules = new Map();

if (rulesDef?.length > 0) {
    for (const rule of rulesDef) {
        let split = rule.toLowerCase().split('=');
        if (split.length != 2) {
            await LogErrorAndExit(`Invalid rule ${rule}. `);
        }

        if (!ACTIVITY_TYPES.map(act => act.toLowerCase()).some(t => split[0] == t)) {
            await LogErrorAndExit(`Invalid activity type in rule ${rule}.`);
        }

        if (!ACTIVITY_VISIBILITY_TYPES.some(t => split[1] == t)) {
            await LogErrorAndExit(`Invalid visibility value in rule ${rule}.`);
        }

        rules.set(split[0], split[1]);
    }
}

const LOGIN_URL = 'https://www.strava.com/login';
const DASHBOARD_URL = 'https://www.strava.com/dashboard';
const BROWSER_DATA_FILE = 'strava_browser.json';
const WEBHOOK_PATH = '/strava-privacy-helper'

try {
    fs.readFileSync(BROWSER_DATA_FILE);
} catch (err) {
    fs.writeFileSync(BROWSER_DATA_FILE, '{}');
}

await GetAppCredentials();
await GetAccessToken();

await inquirer.prompt([{
    type: "table",
    name: "rules",
    message: "Please choose rules to edit activity visibility",
    when: () => rules.size == 0,
    validate: (input) => input.some(i => i != null) || 'Please set at least one rule. ',
    columns: [
        {
            name: "everyone",
            value: "everyone"
        },
        {
            name: "followers_only",
            value: "followers_only"
        },
        {
            name: "only_me",
            value: "only_me"
        }
    ],
    rows: ACTIVITY_TYPES.map(act => {
        return { name: act, value: act.toLowerCase() }
    })
}]).then((answers) => {
    if (!answers.rules) return;

    let rulesOption = '--rules';

    for (let i = 0; i < ACTIVITY_TYPES.length; i++) {
        const act = ACTIVITY_TYPES[i];
        if (answers.rules[i] != null) {
            rules.set(act.toLowerCase(), answers.rules[i]);
            rulesOption += ` ${act}=${answers.rules[i]}`;
        }
    }

    logger.info(`You can use the following option for subsequent runs: ${rulesOption}`);
});

if (options.watch) {
    await RegisterWebhook();
} else {

    await inquirer.prompt([{
        type: 'number',
        message: 'Enter number of activities to process: ',
        name: 'maxActivitiesToCheck',
        when: () => maxActivitiesToCheck == 0,
        validate: (input) => input > 0 && input < 1000 || 'Please enter a number between 1 and 999',
        default: 20
    }]).then((answers) => {
        if (answers.maxActivitiesToCheck) maxActivitiesToCheck = answers.maxActivitiesToCheck;
    });

    let toProcess = await GetRecentActivitesMatchingRules(maxActivitiesToCheck);

    logger.info(`Found ${toProcess.length} activities to process. `);

    for (const act of toProcess) {
        await SetActivityVisibility(act.id, act.newVisibility);
    }

    await context?.close();
    await browser?.close();
}

async function LoginToStrava() {

    logger.info('Checking if logged in. ');

    browser = browser || await chromium.launch({
        headless: !options.headful,
        // proxy: { server: "127.0.0.1:8888" }
    });

    context = context || await browser.newContext({
        storageState: BROWSER_DATA_FILE,
        // proxy: { server: "127.0.0.1:8888" }
    });

    page = page || await context.newPage();

    await page.goto(DASHBOARD_URL, { waitUntil: 'commit' });

    if (page.url() == DASHBOARD_URL) {

        logger.info('Already logged in.');

    } else if (page.url() == LOGIN_URL) {

        await inquirer.prompt([{
            type: 'input',
            message: 'Enter Strava Email Address: ',
            name: 'email',
            when: () => isNullOrWhiteSpace(user.email),
            validate: (input) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input) || 'Please enter a valid email address'
        },
        {
            type: 'password',
            message: 'Enter Strava Password: ',
            name: 'password',
            mask: '*',
            when: () => isNullOrWhiteSpace(user.password) || 'Please enter a valid password',
            validate: (input) => input.length > 2
        },
        ]).then((answers) => {
            if (answers.email) user.email = answers.email;
            if (answers.password) user.password = answers.password;
        });

        logger.info('Logging in.');

        await page.getByPlaceholder('Your Email').click();
        await page.getByPlaceholder('Your Email').fill(user.email);
        await page.getByPlaceholder('Password').click();
        await page.getByPlaceholder('Password').fill(user.password);
        await page.getByLabel('Remember me').check();

        let loginResponsePromise = page.waitForResponse(res => res.url() == 'https://www.strava.com/session' && res.request().method() == 'POST')
        await page.getByRole('button', { name: 'Log In' }).click();

        let loginResponse = await loginResponsePromise;

        let redirectUrl = await loginResponse.headerValue("location");

        if (redirectUrl == DASHBOARD_URL) {
            logger.info('Login successful. ');
            await context.storageState({ path: BROWSER_DATA_FILE });
        } else if (redirectUrl == LOGIN_URL) {
            await LogErrorAndExit('Login failed. ');
        } else {
            await LogErrorAndExit(`Uknown redirect url ${redirectUrl}. Login failed. `);
        }

    }
    else {
        await LogErrorAndExit(`Unknown url detected in login. ${page.url()}`);
    }
}

function isNullOrWhiteSpace(str: string) {
    return str == null || str.trim() == '';
}

async function GetAppCredentials() {
    await LoginToStrava();

    logger.info(`Getting client id and secret`);

    try {
        await page.goto('https://www.strava.com/settings/api');

        user.client_id = await page.locator('[class*=TableRow]').filter({ hasText: 'Client ID' }).getByText(/[0-9]+/).innerText();

        await page.getByRole('button', { name: 'Show' }).first().click();

        user.client_secret = await page.locator('[class*=TableRow]').filter({ hasText: 'Client Secret' }).locator('p').innerText();

        if (isNullOrWhiteSpace(user.client_id) || isNullOrWhiteSpace(user.client_secret)) {
            throw new Error('Could not parse client id or secret. ');
        }
    } catch (error) {
        await LogErrorAndExit(`${error} Make sure you've created an app at https://www.strava.com/settings/api and uploaded an icon for the app. `);
    }
}

async function GetAccessToken() {

    logger.info('Getting access token. ');

    await page.goto(`https://www.strava.com/oauth/authorize?client_id=${user.client_id}&redirect_uri=http://localhost:${port}&response_type=code&scope=activity:read_all`);

    let code: string | null = "";

    await new Promise<void>((resolve, reject) => {
        const tempServer = express().listen(port, async () => {
            await page.click("button#authorize");
            await page.waitForURL(`http://localhost:${port}/?state=&code=*&scope=read,activity:read_all`);

            code = new URL(page.url()).searchParams.get('code');

            tempServer.close();
            resolve();
        });
    });

    let res = await axios.post(`https://www.strava.com/api/v3/oauth/token?client_id=${user.client_id}&client_secret=${user.client_secret}&code=${code}&grant_type=authorization_code`);

    user = { ...user, expires_at: res.data.expires_at, access_token: res.data.access_token, refresh_token: res.data.refresh_token };
}

async function RefreshToken() {
    if (user.expires_at - Math.round(Date.now() / 1000) < 90) {

        logger.info('Refreshing access token. ');

        let res = await axios.post(`https://www.strava.com/api/v3/oauth/token?client_id=${user.client_id}&client_secret=${user.client_secret}&grant_type=refresh_token&refresh_token=${user.refresh_token}`);

        user = { ...user, expires_at: res.data.expires_at, access_token: res.data.access_token, refresh_token: res.data.refresh_token };
    }
}

async function RegisterWebhook() {

    await UnregisterWebhook();

    const app = express();
    var verifyToken = randomUUID();

    app.use(express.json());

    app.get(WEBHOOK_PATH, (req, res) => {
        if (req.query["hub.challenge"] && req.query["hub.verify_token"] && req.query["hub.verify_token"] == verifyToken) {
            res.send({ "hub.challenge": req.query["hub.challenge"] })
        }
        else {
            res.sendStatus(405)
        };
    });

    app.post(WEBHOOK_PATH, (req, res) => {
        logger.debug(JSON.stringify(req.body));

        if (req.body.aspect_type == 'create' && req.body.object_type == 'activity') {
            logger.info(`Found new activity ${req.body.object_id}`);
            ProcessActivity(req.body.object_id);
        }

        res.sendStatus(200);
    });


    await new Promise<void>((resolve) => {
        app.listen(port, () => {
            logger.info(`Webhook server running at http://localhost:${port}`);
            resolve();
        });
    });

    await inquirer.prompt([{
        type: 'input',
        message: 'Enter ngrok auth token: ',
        name: 'ngrok',
        when: () => isNullOrWhiteSpace(ngrokAuth),
        validate: (input) => !isNullOrWhiteSpace(input) || 'Please enter a valid ngrok token for setting up webhook'
    }]).then((answers) => {
        if (answers.ngrok) ngrokAuth = answers.ngrok;
    });

    const url = await ngork.connect({ addr: port, authtoken: ngrokAuth });
    logger.info(`Ngork url registered at ${url}`);

    const form = new formData();
    form.append('client_id', user.client_id);
    form.append('client_secret', user.client_secret);
    form.append('callback_url', url + WEBHOOK_PATH);
    form.append('verify_token', verifyToken);

    try {
        let res = await axios.post('https://www.strava.com/api/v3/push_subscriptions', form, { headers: form.getHeaders() })
        if (res.data.id) {
            logger.info(`Webhook registered with strava. ID = ${res.data.id}`);
            logger.info('New activities will be automatically processed. ');
        }
        else {
            await LogErrorAndExit(`Unknown response. ${JSON.stringify(res.data)}`);
        }
    } catch (error: any) {
        await LogErrorAndExit(`Error registering webhook. ${error} ${JSON.stringify(error.response.data)}`);
    }
}

async function UnregisterWebhook() {

    logger.info(`Checking existing webhook. `);

    try {
        let res = await axios.get(`https://www.strava.com/api/v3/push_subscriptions?client_id=${user.client_id}&client_secret=${user.client_secret}`);
        let id = res.data[0]?.id;
        if (!id) {
            logger.info('No existing webhook found. ');
            return;
        }

        logger.info(`Found existing webhook with id ${id}`);

        logger.info(`Unregestering webhook ${id}.`);

        try {
            const form = new formData();
            form.append('client_id', user.client_id);
            form.append('client_secret', user.client_secret);

            let res = await axios.delete(`https://www.strava.com/api/v3/push_subscriptions/${id}?client_id=${user.client_id}&client_secret=${user.client_secret}`);

            logger.info(`Webhook unregistered succesfuly. `);
        } catch (error: any) {
            await LogErrorAndExit(`Error unregistering webhook. ${error} ${JSON.stringify(error.response.data)}`);
        }

    } catch (error: any) {
        await LogErrorAndExit(`Error checking existing webhook. ${error}`);
    }
}


interface ActivityVisibility {
    id: number,
    newVisibility: string
}

async function GetRecentActivitesMatchingRules(max: number): Promise<Array<ActivityVisibility>> {

    logger.info('Getting recent activities matching the rules. ');

    let res = await axios.get(`https://www.strava.com/api/v3/athlete/activities?per_page=${max}`, {
        headers: {
            'Authorization': `Bearer ${user.access_token}`
        }
    });

    let result: ActivityVisibility[] = [];

    for (const activity of res.data) {
        const activityType = activity.type.toLowerCase();
        if (rules.has(activityType) && rules.get(activityType) != activity.visibility) {
            result.push({ id: activity.id, newVisibility: rules.get(activityType) });
        }
    }

    return result;
}

async function SetActivityVisibility(activityId: number, visibility: string) {

    logger.info(`Setting activity ${activityId} to ${visibility}`);

    await page.goto(`https://www.strava.com/activities/${activityId}/edit`);

    await page.getByText('﹀').click();

    await page.check(`input[value=${visibility}]`);

    await page.getByRole('button', { name: 'Save' }).click();

    logger.info(`Done setting activity visibility. `);
}

async function ProcessActivity(activityId: number) {
    await RefreshToken();
    let res = await axios.get(`https://www.strava.com/api/v3/activities/${activityId}`, {
        headers: {
            'Authorization': `Bearer ${user.access_token}`
        }
    });

    let activity = res.data;

    const activityType = activity.type.toLowerCase();

    if (rules.has(activityType) && rules.get(activityType) != activity.visibility) {
        await SetActivityVisibility(activity.id, rules.get(activityType));
    }
    else {
        logger.info(`Activity ${activityId} does not match any rules. `);
    }
}

async function LogErrorAndExit(msg: string) {
    logger.error(msg);
    await context?.close();
    await browser?.close();
    exit(1);
}

function delay(delay: number) {
    return new Promise(function (fulfill) {
        setTimeout(fulfill, delay)
    });
}