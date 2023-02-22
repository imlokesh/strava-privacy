#!/usr/bin/env node

import 'dotenv/config';
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


const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
        winston.format.printf((info) => `${info.timestamp} [${info.level}] - ${info.message}`)),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'app.log' })
    ],
});

const ACTIVITY_TYPES = ["alpineski", "backcountryski", "canoeing", "crossfit", "ebikeride", "elliptical", "golf", "handcycle", "hike", "iceskate", "inlineskate", "kayaking", "kitesurf", "nordicski", "ride", "rockclimbing", "rollerski", "rowing", "run", "sail", "skateboard", "snowboard", "snowshoe", "soccer", "stairstepper", "standuppaddling", "surfing", "swim", "velomobile", "virtualride", "virtualrun", "walk", "weighttraining", "wheelchair", "windsurf", "workout", "yoga"];
const ACTIVITY_VISIBILITY_TYPES = ["everyone", "followers_only", "only_me"];

const program = new Command();

program
    .option("--strava-email <value>", "Strave login email address. ")
    .option("--strava-password <value>", "Strava login password. ")
    .option("--client-id <value>", "Strava application client id. ")
    .option("--client-secret <value>", "Strava application client secret. ")
    .option("--ngrok-auth <value>", "Ngrok auth token. ")
    .option("--port <value>", "Port for webhook client. ", "8095")
    .option("--num <value>", "Number of activities to process. ", "20")
    .option("--rules <values...>", "Rules to be used to set privacy on activities. ", ["WeightTraining=only_me"])
    .option("--watch", "Watch for new activities. ", false);

program.parse(process.argv);
const options = program.opts();

const stravaEmail = options.stravaEmail || process.env.STRAVA_EMAIL;
const stravaPassword = options.stravaPassword || process.env.STRAVA_PASSWORD;

const clientId = options.clientId || process.env.CLIENT_ID;
const clientSecret = options.clientSecret || process.env.CLIENT_SECRET;

if (!stravaEmail || !stravaPassword) {
    LogAndThrowError('Please specify strava login details. Use -h for options');
}

if (!clientId || !clientSecret) {
    LogAndThrowError('Please specify strava client id and client secret from https://www.strava.com/settings/api. Use -h for options');
}

const maxActivitiesToCheck: number = parseInt(options.num) || 20;
const port: number = parseInt(options.port) || 8095;

const ngrokAuth = options.ngrokAuth || process.env.NGROK_AUTH;

if (!ngrokAuth && options.watch) {
    logger.info('No ngrok auth token was found. Webhook service will be limited. ')
}

const rulesDef: string[] = options.rules;
const rules = new Map();

if (rulesDef.length < 1) {
    LogAndThrowError('Please specify at least one rule. ');
}

for (const rule of rulesDef) {
    let split = rule.toLowerCase().split('=');
    if (split.length != 2) {
        LogAndThrowError(`Invalid rule ${rule}. `);
    }

    if (!ACTIVITY_TYPES.some(t => split[0] == t)) {
        LogAndThrowError(`Invalid activity type in rule ${rule}.`);
    }

    if (!ACTIVITY_VISIBILITY_TYPES.some(t => split[1] == t)) {
        LogAndThrowError(`Invalid visibility value in rule ${rule}.`);
    }

    rules.set(split[0], split[1]);
}

interface OAuthToken {
    expires_at: number,
    refresh_token: string,
    access_token: string
}

let oauth: OAuthToken;

let browser: Browser | undefined, context: Context | undefined, page: Page;

const LOGIN_URL = 'https://www.strava.com/login';
const DASHBOARD_URL = 'https://www.strava.com/dashboard';
const BROWSER_DATA_FILE = 'strava_browser.json';
const WEBHOOK_PATH = '/strava-privacy-helper'

function delay(delay: number) {
    return new Promise(function (fulfill) {
        setTimeout(fulfill, delay)
    });
}

try {
    fs.readFileSync(BROWSER_DATA_FILE);
} catch (err) {
    fs.writeFileSync(BROWSER_DATA_FILE, '{}');
}

async function LoginToStrava() {

    logger.info('Checking if logged in. ');

    browser = browser || await chromium.launch({
        headless: true,
        // proxy: { server: "127.0.0.1:8888" }
    });

    context = context || await browser.newContext({
        storageState: BROWSER_DATA_FILE,
        // proxy: { server: "127.0.0.1:8888" }
    });

    page = page || await context.newPage();

    await page.goto(LOGIN_URL, { waitUntil: 'commit' });

    if (page.url() == DASHBOARD_URL) {

        logger.info('Already logged in.');

    } else if (page.url() == LOGIN_URL) {

        logger.info('Logging in.');

        await page.getByPlaceholder('Your Email').click();
        await page.getByPlaceholder('Your Email').fill(stravaEmail);
        await page.getByPlaceholder('Password').click();
        await page.getByPlaceholder('Password').fill(stravaPassword);
        await page.getByLabel('Remember me').check();

        let loginResponsePromise = page.waitForResponse(res => res.url() == 'https://www.strava.com/session' && res.request().method() == 'POST')
        await page.getByRole('button', { name: 'Log In' }).click();

        let loginResponse = await loginResponsePromise;

        let redirectUrl = await loginResponse.headerValue("location");

        if (redirectUrl == DASHBOARD_URL) {
            logger.info('Login successful. ');
            await context.storageState({ path: BROWSER_DATA_FILE });
        } else if (redirectUrl == LOGIN_URL) {
            throw new Error('Login failed. ');
        } else {
            throw new Error(`Uknown redirect url ${redirectUrl}. Login failed. `);
        }

    }
    else {
        throw new Error(`Unknown url detected in login. ${page.url()}`);
    }
}

async function GetAccessToken() {

    logger.info('Getting access token. ');

    await LoginToStrava();

    await page.goto(`https://www.strava.com/oauth/authorize?client_id=${clientId}&redirect_uri=http://localhost:${port}&response_type=code&scope=activity:read_all`);

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

    let res = await axios.post(`https://www.strava.com/api/v3/oauth/token?client_id=${clientId}&client_secret=${clientSecret}&code=${code}&grant_type=authorization_code`);

    oauth = { expires_at: res.data.expires_at, access_token: res.data.access_token, refresh_token: res.data.refresh_token };
}

async function RefreshToken() {
    if (oauth.expires_at - Math.round(Date.now() / 1000) < 90) {

        logger.info('Refreshing access token. ');

        let res = await axios.post(`https://www.strava.com/api/v3/oauth/token?client_id=${clientId}&client_secret=${clientSecret}&grant_type=refresh_token&refresh_token=${oauth.refresh_token}`);

        oauth = { expires_at: res.data.expires_at, access_token: res.data.access_token, refresh_token: res.data.refresh_token };
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

    app.listen(port, () => {
        logger.info(`Webhook server running at http://localhost:${port}`);
        logger.info('New activities will be automatically processed. ');
    });

    const url = await ngork.connect({ addr: port, authtoken: ngrokAuth });
    logger.info(`Ngork url registered at ${url}`);

    const form = new formData();
    form.append('client_id', clientId);
    form.append('client_secret', clientSecret);
    form.append('callback_url', url + WEBHOOK_PATH);
    form.append('verify_token', verifyToken);

    try {
        let res = await axios.post('https://www.strava.com/api/v3/push_subscriptions', form, { headers: form.getHeaders() })
        if (res.data.id) {
            logger.info(`Webhook registered with strava. ID = ${res.data.id}`);
        }
        else {
            throw new Error(`Unknown response. ${JSON.stringify(res.data)}`);
        }
    } catch (error: any) {
        LogAndThrowError(`Error registering webhook. ${error} ${JSON.stringify(error.response.data)}`);
    }
}

async function UnregisterWebhook() {

    logger.info(`Checking existing webhook. `);

    try {
        let res = await axios.get(`https://www.strava.com/api/v3/push_subscriptions?client_id=${clientId}&client_secret=${clientSecret}`);
        let id = res.data[0]?.id;
        if (!id) {
            logger.info('No existing webhook found. ');
            return;
        }

        logger.info(`Found existing webhook with id ${id}`);

        logger.info(`Unregestering webhook ${id}.`);

        try {
            const form = new formData();
            form.append('client_id', clientId);
            form.append('client_secret', clientSecret);

            let res = await axios.delete(`https://www.strava.com/api/v3/push_subscriptions/${id}?client_id=${clientId}&client_secret=${clientSecret}`);

            logger.info(`Webhook unregistered succesfuly. `);
        } catch (error: any) {
            LogAndThrowError(`Error unregistering webhook. ${error} ${JSON.stringify(error.response.data)}`);
        }

    } catch (error: any) {
        LogAndThrowError(`Error checking existing webhook. ${error}`);
    }
}

interface ActivityVisibility {
    id: number,
    visibility: string
}

async function GetRecentActivitesMatchingRules(max: number): Promise<Array<ActivityVisibility>> {

    logger.info('Getting recent activities matching the rules. ');

    let res = await axios.get(`https://www.strava.com/api/v3/athlete/activities?per_page=${max}`, {
        headers: {
            'Authorization': `Bearer ${oauth.access_token}`
        }
    });

    let result: ActivityVisibility[] = [];

    for (const activity of res.data) {
        const activityType = activity.type.toLowerCase();
        if (rules.has(activityType) && rules.get(activityType) != activity.visibility) {
            result.push({ id: activity.id, visibility: rules.get(activityType) });
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
            'Authorization': `Bearer ${oauth.access_token}`
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

(async () => {

    await GetAccessToken();

    if (options.watch) {
        await RegisterWebhook();
    } else {
        let toProcess = await GetRecentActivitesMatchingRules(maxActivitiesToCheck);

        logger.info(`Found ${toProcess.length} activities to process. `);

        for (const act of toProcess) {
            await SetActivityVisibility(act.id, act.visibility);
        }

        await context?.close();
        await browser?.close();
    }
})();

function LogAndThrowError(msg: string) {
    logger.error(msg);
    throw new Error(msg);
}