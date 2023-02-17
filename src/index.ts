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

const program = new Command();

program
    .option("--strava-email", "Strave login email address", "")
    .option("--strava-password", "Strava login password", "")
    .option("--client-id", "Strava application client id", "")
    .option("--client-secret", "Strava application client secret", "")
    .option("--ngrok-auth", "Ngrok auth token", "")
    .option("--port", "Port for webhook client", "")
    .option("--rules", "Rules to be used to set privacy on activities. ", []);

program.parse(process.argv);
const options = program.opts();

const stravaEmail = options.stravaEmail || process.env.STRAVA_EMAIL;
const stravaPassword = options.stravaPassword || process.env.STRAVA_PASSWORD;

const clientId = options.clientId || process.env.CLIENT_ID;
const clientSecret = options.clientSecret || process.env.CLIENT_SECRET;

if (!stravaEmail || !stravaPassword) {
    logger.error('Please specify strava login details. Use -h for options');
}

if (!clientId || !clientSecret) {
    logger.error('Please specify strava client id and client secret from https://www.strava.com/settings/api. Use -h for options');
}

const port: number = parseInt(options.port || process.env.PORT) || 8095;

const ngrokAuth = options.ngrokAuth || process.env.NGROK_AUTH;

if (!ngrokAuth) {
    logger.info('No ngrok auth token was found. Webhook service will be limited. ')
}

let browser: Browser, context: Context, page: Page;

const LOGIN_URL = 'https://www.strava.com/login';
const DASHBOARD_URL = 'https://www.strava.com/dashboard';
const BROWSER_DATA_FILE = 'strava_browser.json';
const WEBHOOK_PATH = '/strava-privacy-helper'

async function ExitProgram() {
    logger.info('Exiting program. ');

    await context?.close();
    await browser?.close();
}

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
        headless: false,
        proxy: { server: "127.0.0.1:8888" }
    });

    context = context || await browser.newContext({
        storageState: BROWSER_DATA_FILE,
        proxy: { server: "127.0.0.1:8888" }
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

async function RegisterWebhook() {

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
        var x = 22;
    });

    app.listen(port, () => {
        logger.info(`Webhook server running at http://localhost:${port}`);
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
        logger.error(`Error registering webhook. ${error} ${JSON.stringify(error.response.data)}`);
    }
}

async function UnregisterWebhook() {

    logger.info(`Checking existing webhook. `);

    try {
        let res = await axios.get(`https://www.strava.com/api/v3/push_subscriptions?client_id=${clientId}&client_secret=${clientSecret}`);
        let id = res.data[0]?.id;
        if (!id) {
            logger.info('No existing webhook found. ');
            //return;
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
            logger.error(`Error unregistering webhook. ${error} ${JSON.stringify(error.response.data)}`);
        }

    } catch (error: any) {
        logger.error(`Error checking existing webhook. ${error}`);
    }
}

RegisterWebhook().then(UnregisterWebhook);
// GetAppCredentials().catch(err => logger.error(`Error getting app credentials ${err}`)).then(RegisterWebhook)