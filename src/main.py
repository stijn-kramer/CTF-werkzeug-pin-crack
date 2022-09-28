import urllib.request
import os
from flask import Flask, request, render_template, session

app = Flask(__name__)
app.secret_key = os.urandom(32)


@app.route('/')
def index():
    if request.method != 'GET':
        return 405,

    target = request.args.get('target')

    if not target:
        return render_template('index.html')

    if 'history' not in session.keys():
        session['history'] = [target]
    else:
        if target not in session['history']:
            session['history'] += [target]

    if 'https://' in target:
        try:
            r = urllib.request.urlopen(target)
        except Exception as e:
            return render_template('index.html', succes=False, content=e)

        if r:
            try:
                result = r.read().decode('utf-8')
            except Exception as e:
                return render_template('index.html', success=False, content=e)
            return render_template('index.html', success=True, content=result)

    else:
        return render_template('index.html', success=False, content='Please use https://')

    return render_template('index.html')


@app.route('/copyright')
def copyright():
    return render_template('copyright.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
