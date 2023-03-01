# Strava Privacy Helper

This program will help you set privacy settings on your strava activities according to the type of activity. For example, you can set your runs to `everyone` and weight training activities to `only_me`. 

## The problem 

Strava does not have an option to set privacy settings based on activity type. You can only edit privacy settings for all your activities. Furthermore, the Strava API does not allow setting the visibility of your activities either. 

## The Solution

Strava Privacy Helper uses a combination of strava api and web interface to edit visibility setting for your existing or even newer activites with rules based on activity type. It can wait for new activities (`--watch`) by creating a webhook server with the help of [ngrok](https://ngrok.com/). 

# Usage

You can install strava-privacy using npm. 

```
$ npm i -g strava-privacy

...

$ strava-privacy --help
Usage: index [options]

Options:
  --strava-email <value>     Strave login email address.
  --strava-password <value>  Strava login password.
  --ngrok-auth <value>       Ngrok auth token.
  --port <value>             Port for webhook client.  (default: "8095")
  --num <value>              Number of activities to process.
  --rules <values...>        Rules to be used to set privacy on activities.
  --watch                    Watch for new activities.
  --headful                  Run chromium in non-headless mode.
  -h, --help                 display help for command
```

Usage is pretty straightforward but there are a few pre-requisites:
- Strava user login details because the app has to use both strava api and browser automation.
- You must create an app at https://www.strava.com/settings/api. Use `localhost` for callback domain. Also make sure to add an icon to the app, otherwise it would not be usable. 
- In order to use in watch mode, you'll need a free [ngrok](https://ngrok.com/) auth token. 

![strava-privacy screenshot](/screenshot.png?raw=true "Strava Privacy Helper")
*The application is very easy to use. Just follow the on screen instructions.*

# Watch Mode

You can run the application in watch mode that will wait for new activities and automatically set their visibility settings as per your rules. For example:

```
strava-privacy --watch --rules WeightTraining=only_me Walk=only_me
```

For this feature to work properly, you'll need an ngrok auth token. It's free and very easy to signup and obtain. Signup and go to https://dashboard.ngrok.com/get-started/your-authtoken. 

# Bug Reports and Suggestions

Suggestions are welcome, please create an issue if you've any. Also let me know if you find any bugs. 