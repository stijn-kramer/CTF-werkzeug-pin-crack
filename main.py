from flask import Flask, request, render_template

app = Flask(__name__)


@app.route('/')
def index():
    if request.method != 'GET':
        return 405,

    destination = request.args.get('destination')

    if not destination:
        return render_template('index.html')





    return render_template('index.html', content={'destination':destination})


if __name__ == '__main__':
    app.run(debug=True)
