import 'dotenv/config';
import { Browser, chromium, Page } from 'playwright';
import winston from 'winston';
import * as fs from 'fs';
import { Context } from 'vm';

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

let browser: Browser, context: Context, page: Page, clientId: string, clientSecret: string;

const LOGIN_URL = 'https://www.strava.com/login';
const DASHBOARD_URL = 'https://www.strava.com/dashboard';
const BROWSER_DATA_FILE = "browser_data.json";

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
        await page.getByPlaceholder('Your Email').fill(process.env.STRAVA_EMAIL || 'test@gmail.com');
        await page.getByPlaceholder('Password').click();
        await page.getByPlaceholder('Password').fill(process.env.STRAVA_PASSWORD || 'password');
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

async function GetAppCredentials() {
    await LoginToStrava();

    await page.goto('https://www.strava.com/settings/api');

    clientId = await page.locator('[class*=TableRow]').filter({ hasText: 'Client ID' }).getByText(/[0-9]+/).innerText();

    await page.getByRole('button', { name: 'Show' }).first().click();

    clientSecret = await page.locator('[class*=TableRow]').filter({ hasText: 'Client Secret' }).locator('p').innerText();

    await delay(50000);
}

GetAppCredentials().catch(async err => logger.error(`Error getting app credentials. ${err}`) && await ExitProgram());